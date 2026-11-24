/**
 * WispDay — Cloud Intelligence boundary (excerpt)
 * =====================================================================
 * Cloud Intelligence is an optional feature (a setting, on by default) that
 * finds moods/attributes, categories (people, places, emotions…), goals and
 * insights in entries. This excerpt shows exactly what leaves the device and
 * when. Prompts and AI logic live on the server and are not part of the client.
 *
 * What a reviewer can verify:
 *
 *   1. THE SWITCH — AI tasks are only created when the Cloud Intelligence
 *      setting (`ai_features_enabled`) is on. With it off, no entry text is
 *      sent for analysis. (Weather is separate: it sends the public IP to
 *      look up the weather and never sends entry text.)
 *
 *   2. DECRYPT → SANITIZE → SEND — the text is decrypted on the device. If the
 *      key isn't available, the task backs off instead of sending ciphertext.
 *      The plain text is then passed through UniversalSanitizer.sanitize()
 *      before any request is built.
 *
 *   3. WHAT THE SANITIZER REMOVES — see UniversalSanitizer.ts: emails, URLs,
 *      IP addresses, IBANs, card numbers, money amounts, phone numbers,
 *      national ID / passport numbers, GPS coordinates, dates and (aggressive
 *      mode) any 6+ digit number, plus Markdown. It does NOT remove names:
 *      the people/places features need them.
 *
 *   4. WHAT IS SENT — to the WispDay server (`/analyze/`), which relays it to
 *      an AI provider: the sanitized text, a service type, an item id and the
 *      device id. No encryption key, no recovery phrase, no account email.
 */

// ── 1. The switch (BackgroundItemProcessor → task planning) ──────────────────
export const AI_FEATURES_KEY = 'ai_features_enabled';

  const aiFeaturesEnabled = settingsStorage.getBoolean(AI_FEATURES_KEY) ?? true;

 

  if (aiFeaturesEnabled) {
    const aiTasks: Array<{ type: TaskType; missing: boolean; params?: Record<string, any> }> = [
      { type: 'attributes',  missing: forceAll || !item.attribute?.length,  params: taskParams?.attributes },
      { type: 'categories',  missing: forceAll || !item.categories?.length, params: taskParams?.categories },
      // { type: 'summary',     missing: forceAll || !item.itemSummery,        params: taskParams?.summary },
      // goal_detection only added when NOT skipped
      ...(!skipGoalDetection ? [{
        type: 'goal_detection' as TaskType,
        missing: forceAll || !item.goal_detection,
        params: { ...taskParams?.goal_detection, onNewItemOnly: forceAll },
      }] : []),
    ];

    for (const { type, missing, params } of aiTasks) {
      if (!missing) continue;
      const existingTask = existingByType.get(type);
      if (!forceAll && this._shouldSkip(existingTask, missing)) continue;
      tasks.push(this._makeTask(item.id, type, isPremiumUser, params));
    }
  }

  const hasWeather = !forceAll && !!(item.weather && Object.keys(item.weather).length > 0);
  if (!hasWeather) {
    const existingTask = existingByType.get('weather');
    if (forceAll || !this._shouldSkip(existingTask, !hasWeather)) {
      tasks.push(this._makeTask(item.id, 'weather', isPremiumUser));
    }

// ── 2. Decrypt → sanitize (BackgroundItemProcessor._processTask) ─────────────
   private async _processTask(task: ProcessingTask): Promise<void> {
    const netState = await NetInfo.fetch();
    if (!netState.isConnected) return; // Handled safely by loop break

    if (task.lastAttempt && task.attempts > 0) {
      const backoffMs = BACKOFF_MS[Math.min(task.attempts - 1, BACKOFF_MS.length - 1)];
      const elapsed = Date.now() - new Date(task.lastAttempt).getTime();
      if (elapsed < backoffMs) return;
    }

    await this._setTaskStatus(task, 'processing');

    let sanitizedStr = '';
    
    // 1. Check if this specific task actually needs the diary text
    const requiresContent = task.taskType !== 'weather';

    if (requiresContent) {
      let rawContent: string | null = null;

      // Try transient cache/provider first
      if (this.itemContentProvider) {
        rawContent = this.itemContentProvider(task.itemId);
      }

      // Fallback to mirror DB
      if (!rawContent?.trim()) {
        const mirrorItem = await mirrorDb.getItem(task.itemId);
        rawContent = mirrorItem?.content ?? null;
      }

      // Last resort wait
      if (!rawContent?.trim()) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        const mirrorItem = await mirrorDb.getItem(task.itemId);
        rawContent = mirrorItem?.content ?? null;
      }

      // If it's truly empty, back off
      if (!rawContent?.trim()) {
        task.attempts += 1;
        task.lastAttempt = new Date().toISOString();
        task.error = 'Empty content';

        if (task.attempts >= MAX_ATTEMPTS) {
          console.error(`🛑 [Processor] Permanently failed ${task.taskType} for ${task.itemId} after ${task.attempts} attempts: Empty Content`);
          await this._setTaskStatus(task, 'failed');
        } else {
          console.warn(`⚠️ [Processor] Empty content for ${task.itemId} — retry ${task.attempts}/${MAX_ATTEMPTS}`);
          await this._setTaskStatus(task, 'pending');
        }
        return;
      }

      // 2. Safely resolve Decryption (Guest vs Logged In)
      let finalContent = rawContent;
      try {
        const decrypted = encryptionService.decrypt(rawContent);

        if (decrypted && !['🔒 Locked', '⚠️ Invalid Data', '🚫 Unreadable'].includes(decrypted)) {
          // Success: Valid decrypted string
          finalContent = decrypted;
        } else if (decrypted === '🔒 Locked' || decrypted === '🚫 Unreadable') {
          // Caught: It's an encrypted bundle, but the middleware lacks the key (Guest/Locked)
          // We MUST back off. If we proceed, we send cipher-text to the AI.
          task.attempts += 1;
          task.lastAttempt = new Date().toISOString();
          task.error = `Decryption unavailable: ${decrypted}`;

          if (task.attempts >= MAX_ATTEMPTS) {
            console.error(`🛑 [Processor] Permanently failed ${task.taskType} for ${task.itemId}: Key unavailable.`);
            await this._setTaskStatus(task, 'failed');
          } else {
            console.warn(`⚠️ [Processor] Content locked for ${task.itemId} — retry ${task.attempts}/${MAX_ATTEMPTS}`);
            await this._setTaskStatus(task, 'pending');
          }
          return;
        }
        // If decrypted === '⚠️ Invalid Data', it means rawContent lacks ':' 
        // (It is already plain text from the UI cache, so we leave finalContent as rawContent)
      } catch { 
        /* fail silently, retain rawContent */ 
      } 

      // 3. Sanitize the confirmed plain text
      const { sanitized } = sanitize(finalContent, { aggressive: true, stripMarkdown: true });
      sanitizedStr = sanitized;
    }
    // [app boundary] → _executeTask(task, sanitizedStr) calls the request below
  }

// ── 4. What is sent (appApis.ts — the same shape for every analysis type) ────
  const response = await fetch(`${BASE__FULL_URL}/analyze/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      device_id: deviceId,
      item_text: sanitizedText,
      item_id: "",
      service_type: 'attributes',
      attribute_count: count,
    }),
  });
