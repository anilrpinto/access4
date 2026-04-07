import { C, G, LS, AU, GD, SV, EN, ID, RG, AT, log, info, warn, error } from '@/shared/exports.js';

/**
 * Sweeps the Attachments folder for files owned by the current user
 * that are no longer referenced in the decrypted Vault JSON.
 */
export async function runSharedVaultCleanup(vaultData) {
    _runVaultCleanup(vaultData);
}

export async function runPrivateVaultCleanup(privateVaultData) {
    _runVaultCleanup(privateVaultData, C.PRIVATE_ATTACHMENTS_FOLDER_NAME, 'private');
}

/**
 * Core vault Cleanup Logic
 * @param {Object} vaultData - The specific vault (Shared or Private) to check against.
 * @param {string} folderName - The Drive folder to scan (C.ATTACHMENTS_FOLDER_NAME or C.PRIVATE_ATTACHMENTS_FOLDER_NAME).
 * @param {string} vaultType - A label for logging and storage keys ('shared' or 'private').
 */
async function _runVaultCleanup(vaultData, folderName = C.ATTACHMENTS_FOLDER_NAME, vaultType = 'shared') {
    // 1. Validation
    if (!vaultData || Object.keys(vaultData).length === 0) {
        warn(`janitor.${vaultType}`, `Vault data empty. Aborting to prevent accidental deletion.`);
        return;
    }

    // 2. Throttle Check (Unique per User AND per Silo)
    const storageKey = `${vaultType.toLowerCase()}_${C.LAST_GC_RUN_KEY}`;
    const lastRunStr = LS.get(storageKey);
    const lastRun = lastRunStr ? new Date(lastRunStr) : null;
    const now = new Date();
    const twentyFourHours = 24 * 60 * 60 * 1000;

    if (!G.settings.ignore24hCheck) {
        if (lastRun && (now - lastRun < twentyFourHours)) {
            warn(`janitor.${vaultType}`, `Cleanup skipped. Last run: ${lastRun.toLocaleString()}`);
            return;
        }
    } else
        log(`janitor.${vaultType}`, "IGNORING 24H check!!");

    log(`janitor.${vaultType}`, `Starting background cleanup for folder: ${folderName}...`);

    try {
        // 3. Scan Drive
        const driveFiles = await GD.listFilesOwnedByMe(folderName);
        if (driveFiles.length === 0) {
            log(`janitor.${vaultType}`, "No files found in folder. Nothing to clean.");
            return;
        }

        // 4. Crawl local data for active IDs
        const activeIds = new Set();
        const crawl = (obj) => {
            if (!obj || typeof obj !== 'object') return;
            if (Array.isArray(obj.attachments)) {
                obj.attachments.forEach(attr => { if (attr.val) activeIds.add(attr.val); });
            }
            Object.values(obj).forEach(val => { if (val && typeof val === 'object') crawl(val); });
        };
        crawl(vaultData);

        // 5. Identify and Purge Orphans
        const orphans = driveFiles.filter(file => !activeIds.has(file.id));

        if (orphans.length > 0) {
            log(`janitor.${vaultType}`, `Purging ${orphans.length} orphans...`);
            for (const file of orphans) {
                await AT.deleteAttachmentFile(file.id).catch(err => warn(`janitor.${vaultType}.GC`, err.message));
            }
        } else {
            log(`janitor.${vaultType}`, "Drive is in sync. No orphans found.");
        }

        // 6. Update Throttle Timestamp
        LS.set(storageKey, new Date().toISOString());

        info(`janitor.${vaultType}`, "Drive files cleanup completed.");

    } catch (err) {
        error(`janitor.${vaultType}`, "Cleanup failure: " + err.message);
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