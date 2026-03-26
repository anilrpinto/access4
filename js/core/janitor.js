import { C, G, GD, SV, ID, log, info, warn, error } from '@/shared/exports.js';

/**
 * Sweeps the Attachments folder for files owned by the current user
 * that are no longer referenced in the decrypted Vault JSON.
 */
export async function runGarbageCollection(vaultData) {

    if (!vaultData || Object.keys(vaultData).length === 0) {
        warn("janitor.runGarbageCollection", "Vault data is empty or null. Aborting GC to prevent accidental deletion.");
        return;
    }

    // 1. Device-Specific Throttle Check (LocalStorage)
    // We use a unique key based on the user ID so multiple users on 1 device stay separate
    const storageKey = `access4_last_gc_${G.userId}`;
    const lastRunStr = localStorage.getItem(storageKey);
    const lastRun = lastRunStr ? new Date(lastRunStr) : null;
    const now = new Date();
    const twentyFourHours = 24 * 60 * 60 * 1000;

    if (!G.settings.ignore24hBackupCheck) {
        if (lastRun && (now - lastRun < twentyFourHours)) {
            warn("janitor.runGarbageCollection", `Skipping file cleanup. Device last cleaned at: ${lastRun.toLocaleString()}`);
            return;
        }
    } else
        log("janitor.runGarbageCollection", "IGNORING 24H backup check!!");

    log("janitor.runGarbageCollection", "Starting background cleanup...");

    try {
        const driveFiles = await GD.listFilesOwnedByMe(C.ATTACHMENTS_FOLDER_NAME);

        if (driveFiles.length > 0) {

            const activeIds = new Set();
            const crawl = (obj) => {
                if (!obj || typeof obj !== 'object') return;
                if (Array.isArray(obj.attachments)) {
                    obj.attachments.forEach(attr => { if (attr.val) activeIds.add(attr.val); });
                }
                Object.values(obj).forEach(val => { if (val && typeof val === 'object') crawl(val); });
            };
            crawl(vaultData);

            const orphans = driveFiles.filter(file => !activeIds.has(file.id));

            if (orphans.length > 0) {
                log("janitor.runGarbageCollection", `Purging ${orphans.length} orphans...`);
                for (const file of orphans) {
                    await SV.deleteAttachmentFile(file.id).catch(err => warn("janitor.GC", err.message));
                }
            } else {
                log("janitor.runGarbageCollection", "Drive is in sync. No orphans found.");
            }
        }

        // 4. Update LocalStorage (No Vault Save Required!)
        localStorage.setItem(storageKey, new Date().toISOString());

        info("janitor.runGarbageCollection", "Cleanup complete and timestamp updated.");

    } catch (err) {
        error("janitor.runGarbageCollection", "Global GC failure: " + err.message);
    }
}
