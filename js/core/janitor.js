import { C, G, AU, GD, SV, ID, RG, log, info, warn, error } from '@/shared/exports.js';

/*import { C } from '@/shared/constants.js';
import { G } from '@/shared/global.js';
import * as AU from '@/core/auth.js';
import * as GD from '@/core/gdrive.js';
import * as SV from '@/core/server.js';
import * as RG from '@/core/registry.js';

import { log, trace, debug, info, warn, error } from '@/shared/log.js';*/

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

    if (!AU.isAdmin())
        return;

    info("janitor.runVaultAccessHousekeeping", "Background maintenance started");

    try {
        // 1️⃣ Sync the Registry (Delta Fetch)
        // This populates G.keyRegistry.flat.activeDevices
        // We await this so the wrapper has data to work with.
        await RG.syncRegistryDeltas();
        log("janitor.runVaultAccessHousekeeping", "Registry deltas synced from Drive.");

        // 2️⃣ Wait for the Write Lock
        // We don't start the lock here (loginUI already did),
        // we just wait for the promise to resolve to 'write' mode.
        if (G.lockAcquisitionPromise) {
            log("janitor.runVaultAccessHousekeeping", "Waiting for background lock acquisition...");
            await G.lockAcquisitionPromise;
        }

        // 3️⃣ Perform Housekeeping (Only if we got the Write Lock)
        if (G.driveLockState?.mode === "write") {
            log("janitor.runVaultAccessHousekeeping", "Write lock confirmed. Running CEK reconciliation...");

            if (!envelope) {
                log("janitor.runVaultAccessHousekeeping", "Fetching fresh copy from Drive...");
                envelope = (await SV.readEnvelopeFromDrive(C.ENVELOPE_NAME))?.json;
            }

            if (envelope)
                await SV.wrapCEKForRegistryKeys(envelope);

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