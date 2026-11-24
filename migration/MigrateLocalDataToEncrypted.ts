import { encryptionService } from '../middleware/EncryptionMiddleware';
import { powerSync } from '../database/AppDatabase';
import { UploadQueueManager } from '../utils/UploadQueueManager';
import { reencryptLocation } from '../utils/location/locationCodec';

export const migrateLocalDataToEncrypted = async () => {
  console.log("🔒 Starting Migration: Guest Keys -> Master Keys...");

  try {
    // 1. FETCH ALL DATA FIRST (Read-only, completely safe from crashes)
    console.log("🔒 Fetching all local data for migration...");
    const [itemsResult, repliesResult, goalsResult, habitsResult, collectionsResult] = await Promise.all([
      powerSync.getAll('SELECT * FROM items WHERE deleted_at IS NULL'),
      powerSync.getAll('SELECT * FROM item_replies WHERE deleted_at IS NULL'),
      powerSync.getAll('SELECT * FROM goals WHERE deleted_at IS NULL'),
      powerSync.getAll('SELECT * FROM habits WHERE deleted_at IS NULL'),
      powerSync.getAll('SELECT * FROM collections WHERE deleted_at IS NULL')
    ]);

    // 2. PERFORM ALL WRITES IN A SINGLE TRANSACTION
    // If the phone dies anywhere inside this block, SQLite abandons the transaction 
    // and the database remains exactly as it was before the migration started.
    await powerSync.writeTransaction(async (tx) => {
      
      const isEnc = (txt: string) => txt && txt.includes(':') && txt.split(':').length === 3;
      const safeDec = (txt: string) => isEnc(txt) ? (encryptionService.decrypt(txt) || txt) : txt;
      const safeEnc = (txt: string) => txt ? (encryptionService.encrypt(txt) || txt) : txt;

      // --- 1. MIGRATE ITEMS ---
      if (itemsResult.length > 0) {
        console.log(`🔒 Migrating ${itemsResult.length} Items...`);
        for (const row of itemsResult) {
          const plainContent = safeDec(row.content || '');
          const newEncryptedContent = safeEnc(plainContent);

          const plainNotes = safeDec(row.notes || '');
          const newEncryptedNotes = safeEnc(plainNotes);

          // Migrate Categories
          let newEncryptedCategories = row.categories;
          if (row.categories) {
             const plainCategories = safeDec(row.categories);
             newEncryptedCategories = safeEnc(plainCategories);
          }

          let migratedMediaJson = row.media_items;
          if (row.media_items && row.media_items !== '[]') {
            try {
              const mediaArray = JSON.parse(row.media_items);
              const updatedMediaArray = mediaArray.map((m: any) => {
                if (m.encryptedDek && m.dekIv && m.dekTag) {
                  const dekBuffer = encryptionService.unwrapDEK(m.encryptedDek, m.dekIv, m.dekTag);
                  if (dekBuffer) {
                    const newWrapped = encryptionService.wrapDEK(dekBuffer);
                    if (newWrapped) {
                      return {
                        ...m,
                        encryptedDek: newWrapped.encrypted_dek,
                        dekIv: newWrapped.dek_iv,
                        dekTag: newWrapped.dek_tag
                      };
                    }
                  }
                }
                return m;
              });
              migratedMediaJson = JSON.stringify(updatedMediaArray);
            } catch (e) {
              console.warn("Failed to migrate media_items for row", row.id);
            }
          }

          // Migrate Location (guest plain JSON -> encrypted with Master Key).
          // null = empty or unreadable -> COALESCE keeps the current value untouched.
          const newLocation = reencryptLocation(row.location) ?? null;

          await tx.execute(
            `UPDATE items 
             SET content = ?, notes = ?, categories = ?, media_items = ?,
                 location = COALESCE(?, location), _metadata = ?
             WHERE id = ?`,
            [
              newEncryptedContent, newEncryptedNotes, newEncryptedCategories, migratedMediaJson,
              newLocation,
              JSON.stringify({ ...JSON.parse(row._metadata || '{}'), content_ts: Date.now() }),
              row.id 
            ]
          ); 
        }
      }

      // --- 2. MIGRATE ITEM REPLIES ---
      if (repliesResult.length > 0) {
        console.log(`🔒 Migrating ${repliesResult.length} Replies...`);
        for (const row of repliesResult) {
          const plainContent = safeDec(row.content || '');
          const newEncryptedContent = safeEnc(plainContent);

          await tx.execute(
            `UPDATE item_replies SET content = ? WHERE id = ?`,
            [newEncryptedContent, row.id]
          );
        } 
      }

      // --- 3. MIGRATE GOALS ---
      if (goalsResult.length > 0) {
        console.log(`🔒 Migrating ${goalsResult.length} Goals...`);
        for (const row of goalsResult) {
          const newTitle = safeEnc(safeDec(row.title));
          const newDesc = safeEnc(safeDec(row.description));

          let newMilestonesStr = row.milestones;
          if (row.milestones) {
            try { 
               const parsed = JSON.parse(safeDec(row.milestones)); 
               const updated = parsed.map((m: any) => ({
                 ...m,
                 title: safeEnc(safeDec(m.title)) 
               }));
               newMilestonesStr = JSON.stringify(updated);
            } catch(e) {}
          }

          await tx.execute(
            `UPDATE goals SET 
              title = ?, description = ?, milestones = ?,
              _metadata = ?
             WHERE id = ?`,
            [
              newTitle, newDesc, newMilestonesStr,
              JSON.stringify({ ...JSON.parse(row._metadata || '{}'), updated_at_ts: Date.now() }),
              row.id
            ]
          );
        }
      }

      // --- 4. MIGRATE HABITS ---
      if (habitsResult.length > 0) {
        console.log(`🔒 Migrating ${habitsResult.length} Habits...`);
        for (const row of habitsResult) {
          const newTitle = safeEnc(safeDec(row.title));
          const newDesc = safeEnc(safeDec(row.description));

          await tx.execute(
            `UPDATE habits SET 
              title = ?, description = ?, 
              _metadata = ?
             WHERE id = ?`,
            [
              newTitle, newDesc, 
              JSON.stringify({ ...JSON.parse(row._metadata || '{}'), updated_at_ts: Date.now() }),
              row.id
            ]
          );
        }
      }

      // --- 5. MIGRATE COLLECTIONS ---
      if (collectionsResult.length > 0) {
        console.log(`🔒 Migrating ${collectionsResult.length} Collections...`);
        for (const row of collectionsResult) {
          const newName = safeEnc(safeDec(row.name));
          const newDesc = safeEnc(safeDec(row.description));

          await tx.execute(
            `UPDATE collections SET 
              name = ?, description = ?, 
              _metadata = ?
             WHERE id = ?`,
            [
              newName, newDesc, 
              JSON.stringify({ ...JSON.parse(row._metadata || '{}'), updated_at_ts: Date.now() }),
              row.id
            ]
          ); 
        }
      }
    });

    console.log("✅ Database tables migrated successfully.");

  } catch (e) {
    console.error("❌ Failed to migrate database tables. Rolling back transaction.", e);
    // Re-throw so the calling function knows the migration failed
    throw e; 
  }

  // --- 6. MIGRATE PENDING UPLOAD QUEUE ---
  // We do this outside the SQLite transaction because it relies on purely in-memory/JSON states
  try {
    const queue = UploadQueueManager.getQueue();
    let queueModified = false;

    for (const itemId of Object.keys(queue)) {
      const entries = queue[itemId];
      let entryModified = false;

      for (const entry of entries) {
        if (entry.encrypted_dek && entry.dek_iv && entry.dek_tag) {
          const dekBuffer = encryptionService.unwrapDEK(entry.encrypted_dek, entry.dek_iv, entry.dek_tag);
          if (dekBuffer) {
            const newWrapped = encryptionService.wrapDEK(dekBuffer);
            if (newWrapped) {
              entry.encrypted_dek = newWrapped.encrypted_dek;
              entry.dek_iv = newWrapped.dek_iv;
              entry.dek_tag = newWrapped.dek_tag;
              entryModified = true;
            }
          }
        }
      }

      if (entryModified) {
        queueModified = true;
        for (const entry of entries) {
          UploadQueueManager.updateQueueEntry(itemId, entry.tempId, {
            encrypted_dek: entry.encrypted_dek,
            dek_iv: entry.dek_iv,
            dek_tag: entry.dek_tag
          });
        }
      }
    }
    
    if (queueModified) console.log("✅ Upload Queue DEKs Migrated successfully.");
  } catch (e) {
    console.error("❌ Failed to migrate upload queue:", e);
  }

  console.log("✅ Migration Complete. All local data is now encrypted with the Master Key.");
};


// import { encryptionService } from '../middleware/EncryptionMiddleware';
// import { powerSync } from '../database/AppDatabase';
// import { UploadQueueManager } from '../utils/UploadQueueManager';

// export const migrateLocalDataToEncrypted = async () => {
//   console.log("🔒 Starting Migration: Guest Keys -> Master Keys...");

//   // 1. MIGRATE SQLITE DATABASE (ITEMS)
//   const result = await powerSync.getAll('SELECT * FROM items WHERE deleted_at IS NULL');
  
//   if (result.length > 0) {
//     await powerSync.writeTransaction(async (tx) => {
//       for (const row of result) {
//         const isEnc = (txt: string) => txt && txt.includes(':') && txt.split(':').length === 3;

//         const plainContent = isEnc(row.content) ? (encryptionService.decrypt(row.content) || row.content) : (row.content || '');
//         const newEncryptedContent = encryptionService.encrypt(plainContent) || plainContent;

//         const plainNotes = isEnc(row.notes) ? (encryptionService.decrypt(row.notes) || row.notes) : (row.notes || '');
//         const newEncryptedNotes = encryptionService.encrypt(plainNotes) || plainNotes;

//         // 🟢 FIX: Migrate Categories
//         let newEncryptedCategories = row.categories;
//         if (row.categories) {
//            const plainCategories = isEnc(row.categories) ? (encryptionService.decrypt(row.categories) || row.categories) : row.categories;
//            newEncryptedCategories = encryptionService.encrypt(plainCategories) || plainCategories;
//         }

//         let migratedMediaJson = row.media_items;
//         if (row.media_items && row.media_items !== '[]') {
//           try {
//             const mediaArray = JSON.parse(row.media_items);
//             const updatedMediaArray = mediaArray.map((m: any) => {
//               if (m.encryptedDek && m.dekIv && m.dekTag) {
//                 const dekBuffer = encryptionService.unwrapDEK(m.encryptedDek, m.dekIv, m.dekTag);
//                 if (dekBuffer) {
//                   const newWrapped = encryptionService.wrapDEK(dekBuffer);
//                   if (newWrapped) {
//                     return {
//                       ...m,
//                       encryptedDek: newWrapped.encrypted_dek,
//                       dekIv: newWrapped.dek_iv,
//                       dekTag: newWrapped.dek_tag
//                     };
//                   }
//                 }
//               }
//               return m;
//             });
//             migratedMediaJson = JSON.stringify(updatedMediaArray);
//           } catch (e) {
//             console.warn("Failed to migrate media_items for row", row.id);
//           }
//         }

//         await tx.execute(
//           `UPDATE items 
//            SET content = ?, notes = ?, categories = ?, media_items = ?, _metadata = ?
//            WHERE id = ?`,
//           [
//             newEncryptedContent, newEncryptedNotes, newEncryptedCategories, migratedMediaJson,
//             JSON.stringify({ ...JSON.parse(row._metadata || '{}'), content_ts: Date.now() }),
//             row.id 
//           ]
//         ); 
//       }
//     });
//   }

//   // 2. MIGRATE ITEM REPLIES (🟢 FIX: Catch nested text content)
//   try {
//     const repliesResult = await powerSync.getAll('SELECT * FROM item_replies WHERE deleted_at IS NULL');
//     if (repliesResult.length > 0) {
//       await powerSync.writeTransaction(async (tx) => {
//         for (const row of repliesResult) {
//           const isEnc = (txt: string) => txt && txt.includes(':') && txt.split(':').length === 3;
//           const plainContent = isEnc(row.content) ? (encryptionService.decrypt(row.content) || row.content) : (row.content || '');
//           const newEncryptedContent = encryptionService.encrypt(plainContent) || plainContent;

//           await tx.execute(
//             `UPDATE item_replies SET content = ? WHERE id = ?`,
//             [newEncryptedContent, row.id]
//           );
//         }
//       });
//     }
//   } catch (e) {
//     console.error("❌ Failed to migrate replies:", e);
//   }



//   // 3. MIGRATE GOALS (Title, Description, and Milestones only)
//   try {
//     const goalsResult = await powerSync.getAll('SELECT * FROM goals WHERE deleted_at IS NULL');
//     if (goalsResult.length > 0) {
//       console.log(`🔒 Migrating ${goalsResult.length} Goals to Master Key...`);
//       await powerSync.writeTransaction(async (tx) => {
//         for (const row of goalsResult) {
//           const isEnc = (txt: string) => txt && txt.includes(':') && txt.split(':').length === 3;
//           const safeDec = (txt: string) => isEnc(txt) ? (encryptionService.decrypt(txt) || txt) : txt;
//           const safeEnc = (txt: string) => txt ? (encryptionService.encrypt(txt) || txt) : txt;

//           // 1. Decrypt (if guest key was used) and re-encrypt with Master Key
//           const newTitle = safeEnc(safeDec(row.title));
//           const newDesc = safeEnc(safeDec(row.description));

//           // 2. Safely handle nested milestones array
//           let newMilestonesStr = row.milestones;
//           if (row.milestones) {
//             try { 
//                const parsed = JSON.parse(safeDec(row.milestones)); 
//                const updated = parsed.map((m: any) => ({
//                  ...m,
//                  title: safeEnc(safeDec(m.title)) // Encrypt inner milestone titles
//                }));
//                newMilestonesStr = JSON.stringify(updated);
//             } catch(e) {}
//           }

//           await tx.execute(
//             `UPDATE goals SET 
//               title = ?, description = ?, milestones = ?,
//               _metadata = ?
//              WHERE id = ?`,
//             [
//               newTitle, newDesc, newMilestonesStr,
//               JSON.stringify({ ...JSON.parse(row._metadata || '{}'), updated_at_ts: Date.now() }),
//               row.id
//             ]
//           );
//         }
//       });
//     }
//   } catch (e) {
//     console.error("❌ Failed to migrate goals:", e);
//   }


//   // 4. MIGRATE HABITS (Title and Description)
//   try {
//     const habitsResult = await powerSync.getAll('SELECT * FROM habits WHERE deleted_at IS NULL');
//     if (habitsResult.length > 0) {
//       console.log(`🔒 Migrating ${habitsResult.length} Habits to Master Key...`);
//       await powerSync.writeTransaction(async (tx) => {
//         for (const row of habitsResult) {
//           const isEnc = (txt: string) => txt && txt.includes(':') && txt.split(':').length === 3;
//           const safeDec = (txt: string) => isEnc(txt) ? (encryptionService.decrypt(txt) || txt) : txt;
//           const safeEnc = (txt: string) => txt ? (encryptionService.encrypt(txt) || txt) : txt;

//           // Decrypt (if guest key was used) and re-encrypt with Master Key
//           const newTitle = safeEnc(safeDec(row.title));
//           const newDesc = safeEnc(safeDec(row.description));

//           await tx.execute(
//             `UPDATE habits SET 
//               title = ?, description = ?, 
//               _metadata = ?
//              WHERE id = ?`,
//             [
//               newTitle, newDesc, 
//               JSON.stringify({ ...JSON.parse(row._metadata || '{}'), updated_at_ts: Date.now() }),
//               row.id
//             ]
//           );
//         }
//       });
//     }
//   } catch (e) {
//     console.error("❌ Failed to migrate habits:", e);
//   }


//   // 5. MIGRATE COLLECTIONS (Name and Description)
//   try {
//     const collectionsResult = await powerSync.getAll('SELECT * FROM collections WHERE deleted_at IS NULL');
//     if (collectionsResult.length > 0) {
//       console.log(`🔒 Migrating ${collectionsResult.length} Collections to Master Key...`);
//       await powerSync.writeTransaction(async (tx) => {
//         for (const row of collectionsResult) {
//           const isEnc = (txt: string) => txt && txt.includes(':') && txt.split(':').length === 3;
//           const safeDec = (txt: string) => isEnc(txt) ? (encryptionService.decrypt(txt) || txt) : txt;
//           const safeEnc = (txt: string) => txt ? (encryptionService.encrypt(txt) || txt) : txt;

//           // Decrypt (if guest key was used) and re-encrypt with Master Key
//           const newName = safeEnc(safeDec(row.name));
//           const newDesc = safeEnc(safeDec(row.description));

//           await tx.execute(
//             `UPDATE collections SET 
//               name = ?, description = ?, 
//               _metadata = ?
//              WHERE id = ?`,
//             [
//               newName, newDesc, 
//               JSON.stringify({ ...JSON.parse(row._metadata || '{}'), updated_at_ts: Date.now() }),
//               row.id
//             ]
//           ); 
//         }
//       });
//     }
//   } catch (e) {
//     console.error("❌ Failed to migrate collections:", e);
//   }

//   // 6. MIGRATE PENDING UPLOAD QUEUE
//   try {
//     const queue = UploadQueueManager.getQueue();
//     let queueModified = false;

//     for (const itemId of Object.keys(queue)) {
//       const entries = queue[itemId];
//       let entryModified = false;

//       for (const entry of entries) {
//         if (entry.encrypted_dek && entry.dek_iv && entry.dek_tag) {
//           const dekBuffer = encryptionService.unwrapDEK(entry.encrypted_dek, entry.dek_iv, entry.dek_tag);
//           if (dekBuffer) {
//             const newWrapped = encryptionService.wrapDEK(dekBuffer);
//             if (newWrapped) {
//               entry.encrypted_dek = newWrapped.encrypted_dek;
//               entry.dek_iv = newWrapped.dek_iv;
//               entry.dek_tag = newWrapped.dek_tag;
//               entryModified = true;
//             }
//           }
//         }
//       }

//       // Persist the migrated queue items
//       if (entryModified) {
//         queueModified = true;
//         for (const entry of entries) {
//           UploadQueueManager.updateQueueEntry(itemId, entry.tempId, {
//             encrypted_dek: entry.encrypted_dek,
//             dek_iv: entry.dek_iv,
//             dek_tag: entry.dek_tag
//           });
//         }
//       }
//     }
    
//     if (queueModified) console.log("✅ Upload Queue DEKs Migrated successfully.");
//   } catch (e) {
//     console.error("❌ Failed to migrate upload queue:", e);
//   }

//   console.log("✅ Migration Complete. All local data is now encrypted with the Master Key.");
// };