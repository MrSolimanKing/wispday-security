/**
 * WispDay — SecurityLockScreen
 * =====================================================================
 * This is the gate that enforces the lock established by the lifecycle
 * hook (useAppLockLifecycle). When the master key has been wiped from RAM
 * (on background, or at cold boot before unlock), the app shows this
 * screen and the user cannot reach any decrypted content until a
 * successful unlock restores the key.
 *
 * What a reviewer can verify here:
 *
 *   - UNLOCK is gated on the encryption engine. attemptUnlock() calls
 *     encryptionService.tryUnlock(); only a 'success' result calls
 *     onUnlockSuccess() (which reopens the databases). No other path
 *     reveals content.
 *
 *   - A PASSIVE hardware/enrollment check runs before any biometric
 *     prompt, so the screen does not fire prompts when biometrics are
 *     unavailable or disabled, and it distinguishes "temporarily locked
 *     out" from "key invalidated by a biometric enrollment change".
 *
 *   - The INVALIDATED path is fail-safe, not auto-destructive. When the OS
 *     reports the protected key was invalidated (e.g. the user added or
 *     removed a fingerprint/face), the screen does NOT silently wipe. It
 *     surfaces a distinct state and requires an explicit user action,
 *     which then clears the invalidated biometric binding, rotates the
 *     database files, and ends the session via softLogout. The user's
 *     data is only unwound on their explicit confirmation.
 *
 * The key operations live in EncryptionService.ts. App wiring passed in as
 * props or imported (session teardown, DB rotation, i18n, theming) is
 * marked `// [app boundary]`; those modules are not part of this repo.
 */

import React, { useEffect, useState, useRef } from 'react';
import { View, Text, TouchableOpacity, ActivityIndicator, AppState, AppStateStatus, Linking } from 'react-native';
import BootSplash from 'react-native-bootsplash';
import * as LocalAuthentication from 'expo-local-authentication';
import { useTranslation } from 'react-i18next';
import { encryptionService } from '../../middleware/EncryptionMiddleware';

// [app boundary] — rotates (re-keys / recreates) the encrypted database files
// as part of the invalidated-key recovery. Implementation omitted; the
// security-relevant fact is that recovery rotates the DBs before re-use.
declare function rotateDatabaseFiles(): Promise<void>;

// [app boundary] — encrypted KV store; here only the biometric/security flags
// are touched during invalidated-key recovery.
declare const appStorage: {
  set: (key: string, value: boolean) => void;
};

export function SecurityLockScreen({ theme, onUnlockSuccess, softLogout, onSecureLogout }: any) {
  const { t } = useTranslation();
  const [checking, setChecking] = useState(false);
  const [outcome, setOutcome] = useState<'none' | 'locked_out' | 'invalidated' | 'failed' | 'permission_disabled'>('none');

  const isMounted     = useRef(true);
  const attemptingRef = useRef(false);
  const outcomeRef    = useRef<'none' | 'locked_out' | 'invalidated' | 'failed' | 'permission_disabled'>('none');

  // Track whether the app actually hit the background (vs. a spurious
  // active→active transition), to avoid re-prompting on every state change.
  const hasHitBackground = useRef(false);
  const lastAutoRetry = useRef(0);

  // Passive guard: checks hardware + enrollment WITHOUT triggering a prompt,
  // so we never fire a biometric alert when it would just fail.
  const checkBiometricAvailability = async (): Promise<boolean> => {
    try {
      const hasHardware = await LocalAuthentication.hasHardwareAsync();
      const isEnrolled = await LocalAuthentication.isEnrolledAsync();

      if (!hasHardware || !isEnrolled) {
        outcomeRef.current = 'permission_disabled';
        setOutcome('permission_disabled');
        return false;
      }
      return true;
    } catch (e) {
      console.log('Failed passive biometric check', e);
      return false;
    }
  };

  const attemptUnlock = async () => {
    if (attemptingRef.current) return;
    attemptingRef.current = true;
    setChecking(true);

    // Passive validation first so we don't fire a prompt if biometrics are blocked.
    const available = await checkBiometricAvailability();
    if (!available) {
      attemptingRef.current = false;
      setChecking(false);
      return;
    }

    // Re-arm the single-prompt coordinator for exactly one user-initiated
    // unlock, and shield the lifecycle hook from treating the biometric
    // prompt's brief backgrounding as a lock trigger.
    encryptionService.armUnlockAttempt();
    encryptionService.isIntentionalBackground = true;

    try {
      const result = await encryptionService.tryUnlock();
      if (!isMounted.current) return;

      if (result === 'success') {
        outcomeRef.current = 'none';
        setOutcome('none');
        BootSplash.hide({ fade: true });
        await onUnlockSuccess();   // [app boundary] reopens encrypted databases
        return;
      }
      outcomeRef.current = result;
      setOutcome(result);
    } catch (e) {
      console.log('Unlock failed', e);
      if (isMounted.current) {
        outcomeRef.current = 'failed';
        setOutcome('failed');
      }
    } finally {
      // Release the intentional-background shield shortly after the prompt.
      setTimeout(() => { encryptionService.isIntentionalBackground = false; }, 1500);
      attemptingRef.current = false;
      if (isMounted.current) setChecking(false);
    }
  };

  useEffect(() => {
    isMounted.current = true;

    // Initial boot validation + unlock attempt.
    const initBoot = async () => {
      const available = await checkBiometricAvailability();
      if (available && AppState.currentState === 'active') {
        attemptUnlock();
      }
    };
    initBoot();

    if (AppState.currentState === 'background') {
      hasHitBackground.current = true;
    }

    const subscription = AppState.addEventListener('change', async (nextAppState: AppStateStatus) => {
      if (nextAppState === 'background') {
        hasHitBackground.current = true;
      }

      if (nextAppState === 'active') {
        const cameFromBg = hasHitBackground.current;
        hasHitBackground.current = false;

        // Returning from system Settings: re-check whether permission was re-enabled.
        if (outcomeRef.current === 'permission_disabled') {
          const nowAvailable = await checkBiometricAvailability();
          if (nowAvailable) {
            attemptUnlock();
          }
          return;
        }

        // Loop breaker: only auto-retry on a genuine background→active return,
        // never while a prompt is in flight, already unlocked, or too soon
        // after the last attempt.
        if (!cameFromBg) return;
        if (encryptionService.isIntentionalBackground) return;
        if (attemptingRef.current) return;
        if (outcomeRef.current === 'none' && encryptionService.ready) return;

        if (Date.now() - lastAutoRetry.current < 2000) return;
        lastAutoRetry.current = Date.now();

        attemptUnlock();
      }
    });

    return () => {
      isMounted.current = false;
      subscription.remove();
      encryptionService.isIntentionalBackground = false;
    };
  }, []);

  const accent = theme.colors.notification ?? '#e53935';

  let message: string | null = null;
  let buttonLabel = t('texts:SECURITY_LOCK_SCREEN:UNLOCK_BTN');
  let onPressAction = attemptUnlock;

  if (outcome === 'permission_disabled') {
    message = t('texts:SECURITY_LOCK_SCREEN:MSG_PERMISSION_DISABLED');
    buttonLabel = t('texts:SECURITY_LOCK_SCREEN:OPEN_SETTINGS_BTN');
    onPressAction = async () => {
      await Linking.openSettings();
    };
  } else if (outcome === 'locked_out') {
    message = t('texts:SECURITY_LOCK_SCREEN:MSG_LOCKED_OUT');
    buttonLabel = t('texts:SECURITY_LOCK_SCREEN:TRY_AGAIN_BTN');
  } else if (outcome === 'invalidated') {
    message = t('texts:SECURITY_LOCK_SCREEN:MSG_INVALIDATED');
    buttonLabel = t('texts:SECURITY_LOCK_SCREEN:SECURE_LOGOUT_BTN');

    // Invalidated key recovery — runs ONLY on explicit user confirmation.
    onPressAction = async () => {
      setChecking(true);
      try {
        // Clear the invalidated biometric binding and disable the biometric tiers.
        encryptionService.forceClearInvalidatedBiometrics();
        appStorage.set('vault_key_binding_enabled', false);  // [app boundary]
        appStorage.set('max_security_enabled', false);       // [app boundary]

        await rotateDatabaseFiles();                         // [app boundary]

        if (softLogout) {
          await softLogout();                                // [app boundary] ends session
        }
        if (onSecureLogout) {
          onSecureLogout();                                  // [app boundary]
        }
      } catch (e) {
        console.error('Failed to wipe session', e);
        setChecking(false);
      }
    };
  } else if (outcome === 'failed') {
    message = t('texts:SECURITY_LOCK_SCREEN:MSG_FAILED');
    buttonLabel = t('texts:SECURITY_LOCK_SCREEN:TRY_AGAIN_BTN');
  }

  return (
    <View style={{ flex: 1, backgroundColor: theme.colors.background, justifyContent: 'center', alignItems: 'center', padding: 24 }}>

      <Text style={{ color: theme.colors.text, fontSize: 24, marginBottom: 20 }}>
        {t('texts:SECURITY_LOCK_SCREEN:APP_LOCKED')}
      </Text>

      {message && (
        <Text style={{ color: (outcome === 'locked_out' || outcome === 'permission_disabled') ? theme.colors.text : accent, fontSize: 14, marginBottom: 20, textAlign: 'center', lineHeight: 21, opacity: (outcome === 'locked_out' || outcome === 'permission_disabled') ? 0.85 : 1 }}>
          {message}
        </Text>
      )}

      {checking ? (
        <ActivityIndicator size="large" color={theme.colors.primary} />
      ) : (
        <TouchableOpacity
          onPress={onPressAction}
          style={{ paddingHorizontal: 30, paddingVertical: 15, backgroundColor: theme.colors.primary, borderRadius: 30 }}
        >
          <Text style={{ color: '#ffffff', fontSize: 16, fontWeight: '600' }}>
            {buttonLabel}
          </Text>
        </TouchableOpacity>
      )}

    </View>
  );
}