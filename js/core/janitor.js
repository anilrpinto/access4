import { C, G, AU, GD, SV, EN, ID, RG, AT, log, info, warn, error } from '@/shared/exports.js';

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
    const storageKey = `${G.userEmail}::${C.LAST_GC_RUN_KEY}`;
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
                    await AT.deleteAttachmentFile(file.id).catch(err => warn("janitor.GC", err.message));
                }
            } else {
                log("janitor.runGarbageCollection", "Drive is in sync. No orphans found.");
            }
        }

        // 4. Update LocalStorage (No Vault Save Required!)
        localStorage.setItem(storageKey, new Date().toISOString());

        info("janitor.runGarbageCollection", "Drive files cleanup completed.");

    } catch (err) {
        error("janitor.runGarbageCollection", "Global GC failure: " + err.message);
    }
}


/**
 * Runs silently after login to ensure the
 * Registry is fresh and the Envelope is fully wrapped.
 */
export async function runVaultAccessHousekeeping(envelope = null) {
    if (!AU.isAdmin() && !G.recoverySession) return;

    info("janitor.runVaultAccessHousekeeping", "Vault access housekeeping started");

    try {
        // 1️⃣ Sync the Registry first
        await RG.syncRegistryDeltas(true);

        // 2️⃣ Escalate ONLY if needed
        if (G.driveLockState?.mode !== "write") {
            log("janitor.runVaultAccessHousekeeping", "Escalating to write lock...");

            // We use the 'try' version because we want a boolean, not an exception
            const success = await SV.tryAcquireEnvelopeWriteLock();

            log("janitor.runVaultAccessHousekeeping", `Escalation result: ${success ? 'SUCCESS' : 'FAILED'}`);

            if (!success) {
                warn("janitor.runVaultAccessHousekeeping", "Maintenance deferred: Lock held by another device.");
                return; // Exit early; we can't do maintenance in Read-Only
            }
        }

        // 3️⃣ Perform Maintenance (We definitely have a write lock now)
        // 3️⃣ FETCH TRUTH: Get the absolute latest envelope from Drive
        const driveData = await EN.readEnvelopeFromDrive();
        const freshEnvelope = driveData?.json;

        if (freshEnvelope) {
            // Reconcile and write back to Drive
            await SV.wrapCEKForRegistryKeys(freshEnvelope);

            if (G.recoverySession) {
                log("janitor.housekeeping", "Recovery complete. Wiping session transients.");
                G.recoverySession = false;
                G.recoveryCEK = null;
            }
            log("janitor.runVaultAccessHousekeeping", "Vault access fully synchronized.");
        }

    } catch (err) {
        error("janitor.runVaultAccessHousekeeping", "Background maintenance failed:", err.message);
    } finally {
        log("janitor.runVaultAccessHousekeeping", "Maintenance cycle ended.");
    }
}