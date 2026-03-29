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

    if (!AU.isAdmin() && !G.recoverySession)
        return;

    info("janitor.runVaultAccessHousekeeping", "Vault access housekeeping started", G.recoverySession? "for recovery run (non admin included)" : "");

    try {

        // 1️⃣ BYPASS CACHE: Force a full scan of the Registry folder on Drive
        await RG.syncRegistryDeltas(true);

        // 2️⃣ ESCALATE: Attempt to upgrade to Write Mode
        if (G.driveLockState?.mode !== "write") {
            log("janitor.runVaultAccessHousekeeping", "Escalating to write lock...");

            // We assign the execution to the global promise so Step 3 can await it,
            // and any UI spinners can see that we are "Busy Locking".
            G.lockAcquisitionPromise = SV.tryAcquireEnvelopeWriteLock();
        }

        // 3️⃣ WAIT: Ensure the acquisition (new or existing) is finished
        if (G.lockAcquisitionPromise) {
            // We await the result of the escalation attempt
            const success = await G.lockAcquisitionPromise;
            log("janitor.runVaultAccessHousekeeping", `Escalation result: ${success ? 'SUCCESS' : 'FAILED'}`);
        }

        if (G.driveLockState?.mode === "write") {

            // 3️⃣ FETCH TRUTH: Get the absolute latest envelope from Drive
            const driveData = await EN.readEnvelopeFromDrive();
            const freshEnvelope = driveData?.json;

            if (freshEnvelope) {
                // This now reconciles the fresh envelope against the full Registry scan
                await SV.wrapCEKForRegistryKeys(freshEnvelope);

                // Only clear recovery once we have successfully written the
                // new device's wrapped key into the envelope on Drive.
                if (G.recoverySession) {
                    log("janitor.housekeeping", "Recovery maintenance complete. Wiping session CEK.");
                    G.recoverySession = false;
                    G.recoveryCEK = null;
                }

                log("janitor.runVaultAccessHousekeeping", "Vault access fully synchronized with Drive truth.");
            }

            log("janitor.runVaultAccessHousekeeping", "Envelope housekeeping complete.");
        } else {
            warn("janitor.runVaultAccessHousekeeping", "App is in Read-Only mode. Skipping CEK wrapping.");
        }

        // 4️⃣ Trigger optional Garbage Collection (Old backups/temp files)
        // await SV.runGarbageCollection();

    } catch (err) {
        error("janitor.runVaultAccessHousekeeping", "Background maintenance failed:", err.message);
    } finally {
        log("janitor.runVaultAccessHousekeeping", "Maintenance cycle ended.");
    }
}