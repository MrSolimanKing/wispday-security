// import { MMKV } from 'react-native-mmkv';
import { createMMKV, MMKV } from 'react-native-mmkv';
import { Item, MOOD_CONFIG } from '../types/types';
import { encryptionService } from '../middleware/EncryptionMiddleware';
import { sanitize } from '../utils/UniversalSanitizer';

interface ProcessedItemData {
  content: string;
  selectedMood: string;
  date: string;
  itemId: string;
}

interface AIResponse {
  summary: string;        // grounded overview of the entity in the user's own entries
  patterns: string[];     // evidence-based observations tied to real entries / mood data
  recommendations: string[]; // reflection questions for the user to journal on (NOT advice)
  processedAt: string;
  totalItemsAnalyzed: number;
}

interface ProcessingResult {
  shouldProcess: boolean;
  newItems: ProcessedItemData[];
  previousInsight: AIResponse | null;
  totalNewItems: number;
}

/**
 * Ground-truth stats computed over ALL of the entity's entries.
 * Mood is expressed as WORDS -> counts (never the raw 1-6 number, never an
 * average — the mood values are categorical labels, not a measurable scale).
 * The frontend maps its existing EntityStats into this shape.
 */
interface InsightStats {
  totalAppearances: number;
  firstAppearance: string;
  lastAppearance: string;
  moodDistribution: Record<string, number>;            // { happy: 8, anxious: 1 }
  coOccurringEntities: { name: string; count: number }[];
  crossCategoryEntities: { name: string; category: string; count: number }[];
  itemsByMonth: Record<string, number>;                // { '2026-03': 5 }
}

class AIEntityProcessor {
  private static instance: AIEntityProcessor;

  // ✅ Lazy Async Initialization variables
  private aiStorage: MMKV | null = null;
  private initPromise: Promise<MMKV> | null = null;

  static getInstance(): AIEntityProcessor {
    if (!AIEntityProcessor.instance) {
      AIEntityProcessor.instance = new AIEntityProcessor();
    }
    return AIEntityProcessor.instance;
  }

  // ✅ Safely get the encrypted MMKV instance
  private async getStorage(): Promise<MMKV> {
    if (this.aiStorage) return this.aiStorage;

    if (!this.initPromise) {
      this.initPromise = (async () => {
        console.log('🔐 Initializing Encrypted AI Cache...');
        // Fetch the device key securely
        const deviceKey = await encryptionService.getOrGenerateDeviceKey();

        this.aiStorage = createMMKV({
          id: 'ai-processing-cache',
          encryptionKey: deviceKey,
        });

        console.log('✅ Encrypted AI Cache Ready');
        return this.aiStorage;
      })();
    }

    return this.initPromise;
  }

  /**
   * Get storage keys for entity processing
   */
  private getStorageKeys(entityName: string, entityCategory: string) {
    const baseKey = `${entityName.toLowerCase()}_${entityCategory.toLowerCase()}`;
    return {
      processedIds: `${baseKey}_processed_itemids`,
      aiResponse: `${baseKey}_processed_ai_response`,
    };
  }

  /**
   * Get processed item IDs from storage
   */
  private async getProcessedItemIds(entityName: string, entityCategory: string): Promise<string[]> {
    const { processedIds } = this.getStorageKeys(entityName, entityCategory);
    try {
      const storage = await this.getStorage();
      const stored = storage.getString(processedIds);
      return stored ? JSON.parse(stored) : [];
    } catch (error) {
      console.error('Error loading processed item IDs:', error);
      return [];
    }
  }

  /**
   * Get previous AI response from storage
   */
  private async getPreviousAIResponse(entityName: string, entityCategory: string): Promise<AIResponse | null> {
    const { aiResponse } = this.getStorageKeys(entityName, entityCategory);
    try {
      const storage = await this.getStorage();
      const stored = storage.getString(aiResponse);
      return stored ? JSON.parse(stored) : null;
    } catch (error) {
      console.error('Error loading previous AI response:', error);
      return null;
    }
  }

  /**
   * Store processed item IDs
   */
  private async storeProcessedItemIds(
    entityName: string,
    entityCategory: string,
    itemIds: string[]
  ): Promise<void> {
    const { processedIds } = this.getStorageKeys(entityName, entityCategory);
    try {
      const storage = await this.getStorage();
      storage.set(processedIds, JSON.stringify(itemIds));
      console.log(`✅ Stored ${itemIds.length} processed item IDs for ${entityName}`);
    } catch (error) {
      console.error('Error storing processed item IDs:', error);
    }
  }

  /**
   * Store AI response
   */
  private async storeAIResponse(
    entityName: string,
    entityCategory: string,
    response: AIResponse
  ): Promise<void> {
    const { aiResponse } = this.getStorageKeys(entityName, entityCategory);
    try {
      const storage = await this.getStorage();
      storage.set(aiResponse, JSON.stringify(response));
      console.log(`✅ Stored AI response for ${entityName}`);
    } catch (error) {
      console.error('Error storing AI response:', error);
    }
  }

  /**
   * Format item data for AI processing
   */
  private formatItemForAI(item: Item): ProcessedItemData {
    // Safely extract the mood, falling back to 'none' for 0 or undefined
    const safeMoodValue = item.selectedMood ?? 0;
    const moodDescription = safeMoodValue > 0 
      ? MOOD_CONFIG[safeMoodValue as keyof typeof MOOD_CONFIG]?.description ?? 'none'
      : 'none';

    const date = new Date(item.timestamp);

    const { sanitized } = sanitize(item.content, { aggressive: true, stripMarkdown: true });

    return {
      content: sanitized,
      selectedMood: moodDescription,
      date: date.toLocaleDateString('en', {
        weekday: 'short',
        month: 'short',
        day: 'numeric',
        year: 'numeric',
      }),
      itemId: item.id,
    };
  } 

  /**
   * Prepare data for AI processing - only new items
   */
  async prepareProcessingData(
    entityName: string,
    entityCategory: string,
    entityItems: Item[]
  ): Promise<ProcessingResult> {
    console.log(`🔍 Preparing AI data for ${entityName} (${entityCategory})`);

    // Get previously processed item IDs
    const processedIds = await this.getProcessedItemIds(entityName, entityCategory);
    console.log(`📋 Previously processed: ${processedIds.length} items`);

    // Filter out already processed items
    const newItems = entityItems.filter(item => !processedIds.includes(item.id));
    console.log(`🆕 New items to process: ${newItems.length}`);

    // Get previous AI insight
    const previousInsight = await this.getPreviousAIResponse(entityName, entityCategory);

    // Determine if we should process
    const shouldProcess = newItems.length > 0;

    if (!shouldProcess) {
      console.log(`⏭️ No new items to process for ${entityName}`);
      return {
        shouldProcess: false,
        newItems: [],
        previousInsight,
        totalNewItems: 0,
      };
    }

    // Format new items for AI
    const formattedNewItems = newItems.map(item => this.formatItemForAI(item));

    console.log(`✅ Prepared ${formattedNewItems.length} new items for AI processing`);

    return {
      shouldProcess: true,
      newItems: formattedNewItems,
      previousInsight,
      totalNewItems: newItems.length,
    };
  }

  /**
   * Build the DATA payload sent to the backend.
   *
   * NOTE: Prompt/instructions now live on the BACKEND. This method ships only
   * raw data the backend uses to construct the prompt itself:
   *   - GROUND-TRUTH STATS computed over ALL of the entity's entries (exact,
   *     never recomputed by the AI). Mood is sent as WORDS + distribution,
   *     never as the raw 1-6 number and never as an average (the numbers are
   *     categorical labels, not a scale).
   *   - A CAPPED sample of the most recent entries' full text for the AI to
   *     actually read. Capped for privacy (less plaintext leaves the device)
   *     and cost. Stats still reflect the full history.
   *   - The previous insight, when this is an incremental update.
   */
  buildInsightPayload(
    entityName: string,
    entityCategory: string,
    processingData: ProcessingResult,
    stats: InsightStats,
    textSampleCap: number = 10
  ): string {
    const { newItems, previousInsight } = processingData;

    // Most-recent N entries (full text) for the AI to read.
    const recentSample = newItems
      .slice(-textSampleCap)
      .map(item => ({
        content: item.content,
        mood: item.selectedMood, // WORD: 'happy' | 'anxious' | ... never a number
        date: item.date,
      }));

    const payload = {
      entityName,
      entityCategory,

      // ── GROUND TRUTH (computed over ALL entries, exact) ──
      stats: {
        totalAppearances: stats.totalAppearances,
        firstAppearance: stats.firstAppearance,
        lastAppearance: stats.lastAppearance,
        // mood as word -> count, NEVER an average
        moodDistribution: stats.moodDistribution, // e.g. { happy: 8, anxious: 1 }
        coOccurringEntities: stats.coOccurringEntities, // [{ name, count }]
        crossCategoryEntities: stats.crossCategoryEntities, // [{ name, category, count }]
        itemsByMonth: stats.itemsByMonth, // { '2026-03': 5, ... }
      },

      // ── MUSCLE (capped recent text the AI reads) ──
      textSample: recentSample,
      textSampleCount: recentSample.length,

      previousInsight: previousInsight
        ? {
            summary: previousInsight.summary,
            patterns: previousInsight.patterns,
            recommendations: previousInsight.recommendations,
            totalItemsAnalyzed: previousInsight.totalItemsAnalyzed,
          }
        : null,
    };

    return JSON.stringify(payload);
  }

  /**
   * Process AI response and store results
   */
  async processAIResponse(
    entityName: string,
    entityCategory: string,
    newItemIds: string[],
    aiResponseText: string,
    totalItemsAnalyzed: number
  ): Promise<AIResponse> {
    try {
      // Parse AI response
      const aiResponse = this.parseAIResponse(aiResponseText, totalItemsAnalyzed);

      // Get existing processed IDs and add new ones
      const existingProcessedIds = await this.getProcessedItemIds(entityName, entityCategory);
      const updatedProcessedIds = [...existingProcessedIds, ...newItemIds];

      // Store updated processed IDs
      await this.storeProcessedItemIds(entityName, entityCategory, updatedProcessedIds);

      // Store AI response
      await this.storeAIResponse(entityName, entityCategory, aiResponse);

      console.log(`✅ Successfully processed and stored AI response for ${entityName}`);
      console.log(`📊 Total items processed: ${updatedProcessedIds.length}`);

      return aiResponse;
    } catch (error) {
      console.error('Error processing AI response:', error);
      throw error;
    }
  }

  /**
   * Parse AI response text into structured format
   */
  private parseAIResponse(responseText: string, totalItemsAnalyzed: number): AIResponse {
    try {
      // Try to extract JSON from the response
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return {
          summary: parsed.summary || 'Analysis completed',
          patterns: Array.isArray(parsed.patterns) ? parsed.patterns : [],
          recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations : [],
          processedAt: new Date().toISOString(),
          totalItemsAnalyzed,
        };
      }

      // Fallback parsing if JSON extraction fails
      return this.parseUnstructuredResponse(responseText, totalItemsAnalyzed);
    } catch (error) {
      console.error('Error parsing AI response:', error);
      return this.getFallbackResponse(totalItemsAnalyzed);
    }
  }

  /**
   * Parse unstructured AI response
   */
  private parseUnstructuredResponse(responseText: string, totalItemsAnalyzed: number): AIResponse {
    const lines = responseText.split('\n').filter(line => line.trim());

    return {
      summary:
        lines.find(line => line.toLowerCase().includes('summary'))?.split(':')[1]?.trim() ||
        lines[0]?.substring(0, 200) ||
        'Analysis completed',
      patterns: lines
        .filter(line => line.includes('•') || line.includes('-') || line.toLowerCase().includes('pattern'))
        .slice(0, 4)
        .map(line => line.replace(/^[•\-\d.]\s*/, '').trim()),
      recommendations: lines
        .filter(line => line.toLowerCase().includes('recommend') || line.includes('?'))
        .slice(0, 3)
        .map(line => line.replace(/^[•\-\d.]\s*/, '').trim()),
      processedAt: new Date().toISOString(),
      totalItemsAnalyzed,
    };
  }

  /**
   * Fallback response when parsing fails
   */
  private getFallbackResponse(totalItemsAnalyzed: number): AIResponse {
    return {
      summary: `Analysis completed for ${totalItemsAnalyzed} entries.`,
      patterns: [],
      recommendations: [],
      processedAt: new Date().toISOString(),
      totalItemsAnalyzed,
    };
  }

  /**
   * Get cached AI response (for immediate display)
   */
  async getCachedInsight(entityName: string, entityCategory: string): Promise<AIResponse | null> {
    return await this.getPreviousAIResponse(entityName, entityCategory);
  }

  /**
   * Clear cache for entity (useful for debugging or reset)
   */
  async clearEntityCache(entityName: string, entityCategory: string): Promise<void> {
    const { processedIds, aiResponse } = this.getStorageKeys(entityName, entityCategory);
    try {
      const storage = await this.getStorage();
      storage.remove(processedIds);
      storage.remove(aiResponse);
      console.log(`🗑️ Cleared cache for ${entityName} (${entityCategory})`);
    } catch (error) {
      console.error('Error clearing cache:', error);
    }
  }

  /**
   * Get processing statistics
   */
  async getProcessingStats(entityName: string, entityCategory: string): Promise<{
    totalProcessed: number;
    lastProcessed: string | null;
    hasCache: boolean;
  }> {
    const processedIds = await this.getProcessedItemIds(entityName, entityCategory);
    const previousInsight = await this.getPreviousAIResponse(entityName, entityCategory);

    return {
      totalProcessed: processedIds.length,
      lastProcessed: previousInsight?.processedAt || null,
      hasCache: previousInsight !== null,
    };
  }


  /**
   * Completely wipe the AI processing cache and reset the processor.
   * Call this during a secure logout or when biometric keys are invalidated.
   */
  async reset(): Promise<void> {
    try {
      if (this.aiStorage) {
        this.aiStorage.clearAll();
        console.log('🗑️ [AIEntityProcessor] Cleared all stored AI insights.');
      }
    } catch (error) { 
      console.error('❌ [AIEntityProcessor] Error clearing AI storage:', error);
    } finally {
      // Reset initialization state so it re-fetches the new device key on next login
      this.aiStorage = null;
      this.initPromise = null;
      console.log('✅ [AIEntityProcessor] Reset complete.');
    }
  }

}

export const aiEntityProcessor = AIEntityProcessor.getInstance();
export type { AIResponse, ProcessedItemData, ProcessingResult, InsightStats };