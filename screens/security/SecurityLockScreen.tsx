// SecurityLockScreen.tsx
import React, { useEffect, useState, useRef } from 'react';
import { View, Text, TouchableOpacity, ActivityIndicator, AppState, AppStateStatus, Linking } from 'react-native';
import BootSplash from "react-native-bootsplash";
import * as LocalAuthentication from 'expo-local-authentication';
import { encryptionService } from '../../middleware/EncryptionMiddleware';
import { rotateDatabaseFiles } from '../../database/AppDatabase';
import { appStorage } from '../../storage/AppStorage';
import { useTranslation } from 'react-i18next'; // Added translation import

export function SecurityLockScreen({ theme, onUnlockSuccess, softLogout, onSecureLogout }: any) {
  const { t } = useTranslation(); // Added useTranslation Hook
  const [checking, setChecking] = useState(false);
  const [outcome, setOutcome]   = useState<'none' | 'locked_out' | 'invalidated' | 'failed' | 'permission_disabled'>('none');

  const isMounted     = useRef(true);
  const attemptingRef = useRef(false);
  const outcomeRef    = useRef<'none' | 'locked_out' | 'invalidated' | 'failed' | 'permission_disabled'>('none');

  // 🛡️ Track if the app ACTUALLY hit the background
  const hasHitBackground = useRef(false);
  const lastAutoRetry = useRef(0);

  // 🛡️ PASSIVE SECURITY GUARD: Checks hardware and permission status without triggering a prompt
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

    // Run passive validation first to ensure we don't fire an alert if blocked
    const available = await checkBiometricAvailability();
    if (!available) {
      attemptingRef.current = false;
      setChecking(false);
      return;
    }

    encryptionService.armUnlockAttempt();
    encryptionService.isIntentionalBackground = true;

    try {
      let result: Awaited<ReturnType<typeof encryptionService.tryUnlock>>;
      try {
        result = await encryptionService.tryUnlock();
      } finally {
        // Face ID is done: from here on a trip to the background is a real one again (it used to
        // stay "intentional" until the whole unlock had finished – leaving the app then skipped
        // the lock and the next return showed no Face ID).
        setTimeout(() => { encryptionService.isIntentionalBackground = false; }, 1500);
      }
      if (!isMounted.current) return;

      if (result === 'success') {
        outcomeRef.current = 'none';
        setOutcome('none');
        BootSplash.hide({ fade: true });
        // Never wait forever: if reopening hangs, the button comes back (and the next return
        // asks for Face ID again) instead of a spinner that blocks every later attempt.
        let timer: ReturnType<typeof setTimeout> | null = null;
        await Promise.race([
          Promise.resolve(onUnlockSuccess()),
          new Promise<void>((r) => { timer = setTimeout(r, 15000); }),
        ]);
        if (timer) clearTimeout(timer);
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
      attemptingRef.current = false;
      if (isMounted.current) setChecking(false);
    }
  };

  useEffect(() => {
    isMounted.current = true;

    // 1. Initial boot validation and check
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
      // 2. Mark when the app genuinely leaves the screen
      if (nextAppState === 'background') {
        hasHitBackground.current = true;
      }

      if (nextAppState === 'active') {
        const cameFromBg = hasHitBackground.current;
        hasHitBackground.current = false; // Reset for next time

        // If coming back from system Settings, verify if they re-enabled permission
        if (outcomeRef.current === 'permission_disabled') {
          const nowAvailable = await checkBiometricAvailability();
          if (nowAvailable) {
            attemptUnlock();
          }
          return;
        }

        // 🛡️ CRITICAL LOOP BREAKER:
        if (!cameFromBg) return;
        if (encryptionService.isIntentionalBackground) return;
        if (attemptingRef.current) return;
        // (Keys already in memory → attemptUnlock finishes without a Face ID prompt.)

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
     
    onPressAction = async () => {
      setChecking(true);
      try {  
        encryptionService.forceClearInvalidatedBiometrics();
        appStorage.set('vault_key_binding_enabled', false);
        appStorage.set('max_security_enabled', false);
 
        await rotateDatabaseFiles();
        
        if (softLogout) {
          await softLogout();
        }

        if (onSecureLogout) {
          onSecureLogout();
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