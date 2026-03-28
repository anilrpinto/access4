import { C, G, AU, SV, CR, ID, AT, U, log, trace, debug, info, warn, error } from '@/shared/exports.js';
import { showSilentToast } from '@/ui/uihelper.js';

const RECOVERY_STRING_PREFIX = "access4recoveryv1";

export async function runAdminBackup(pwd, vaultData, isAuto = true, onBackup = null, onSkip = null) {
    log("backup.runAdminBackup", `Starting backup (Mode: ${isAuto ? 'Auto' : 'Manual'})`);

    if (!AU.isAdmin()) return; // Non-admins never backup

    const today = new Date().toISOString().split('T')[0];

    const scopedKey = `${G.userEmail}::${C.LAST_AUTO_BACKUP_KEY}`;

    if (isAuto) {
        // Daily Throttling Logic
        const lastBackup = localStorage.getItem(scopedKey);
        if (lastBackup === today) {
            info("backup.runAdminBackup", "Auto-backup skipped: already ran today.");
            if (onSkip) onSkip();
            return;
        }
    } else {
        try {
            if (!pwd || pwd.length < C.PASSWORD_MIN_LEN) throw new Error("Invalid password, try again");

            const id = await ID.loadIdentity();
            await ID.verifyPasswordVerifier(id.passwordVerifier, await CR.deriveKey(pwd, id.kdf));
        } catch (e) {
            throw new Error("Invalid Master Password");
        }
    }

    // 2. EXECUTION LOGIC (Master Bundle ZIP)
    try {
        const fullTs = new Date().toISOString().replace(/[:.]/g, '-');
        const prefix = isAuto ? "A" : "M";
        const bundleName = `${prefix}-Access4_MASTER_BUNDLE_${U.getLocalTimestamp()}_${G.userEmail.slice(0, -15)}.zip`;

        const vaultJson = JSON.stringify(vaultData, null, 2);

        // --- Create the Master Bundle ZIP ---
        const masterZipWriter = new window.zip.ZipWriter(new window.zip.BlobWriter("application/zip"));

        // --- STEP A: Internal Data ZIP (The Core) ---
        const internalZipWriter = new window.zip.ZipWriter(new window.zip.BlobWriter("application/zip"));

        // A1. Add the main Vault JSON
        await internalZipWriter.add("vault_data.json", new window.zip.TextReader(vaultJson), {
            password: pwd,
            zipCrypto: true
        });

        // A2. ATTACHMENT PROCESSING: Fetch, Decrypt, and Pack
        const allAttachments = [];
        vaultData.groups.forEach(g => {
            if (g.items) {
                g.items.forEach(i => {
                    if (i.attachments && i.attachments.length > 0) {
                        i.attachments.forEach(a => {
                            // Use 'label' to match your JSON schema
                            allAttachments.push({
                                ...a,
                                itemName: i.label || i.id || "Unknown_Item"
                            });
                        });
                    }
                });
            }
        });

        if (allAttachments.length > 0) {
            info("backup.runAdminBackup", `Processing ${allAttachments.length} attachments...`);

            for (const attach of allAttachments) {
                try {
                    // Use your validated Envelope logic to get plaintext bytes
                    const plaintext = await AT.openAttachment(attach);

                    // If openAttachment returns an ArrayBuffer, this converts it.
                    // If it's already a Uint8Array, this is a safe no-op.
                    const dataToZip = new Uint8Array(plaintext);

                    if (dataToZip.length === 0) {
                        warn("backup.runAdminBackup", `Decrypted data for ${attach.key} is 0 bytes!`);
                    }

                    // Path formatting: "attachments/ItemName_FileName.ext"
                    // We sanitize the item name to prevent ZIP path errors
                    const itemName = attach.itemName || "Unknown";
                    const safeItemName = itemName.replace(/[^a-z0-9]/gi, '_');
                    const zipPath = `attachments/${safeItemName}_${attach.key}`;

                    await internalZipWriter.add(zipPath, new window.zip.Uint8ArrayReader(dataToZip), {
                        password: pwd,
                        zipCrypto: true
                    });

                    log("backup.runAdminBackup", `Bundled ${dataToZip.length} bytes: ${zipPath}`);
                } catch (err) {
                    // Log the error but keep the backup moving
                    error("backup.runAdminBackup", `Failed to bundle ${attach.key}: ${err.message}`, err);
                }
            }
        }

        const internalZipBlob = await internalZipWriter.close();
        await masterZipWriter.add("1-Encrypted_Data.zip", new window.zip.BlobReader(internalZipBlob));

        // 2. Add the Standalone HTML Recovery
        const htmlBlob = await generateRecoveryHTML(vaultJson, pwd);
        await masterZipWriter.add("2-Recovery_Standalone.html", new window.zip.BlobReader(htmlBlob));

        // 3. Add the Recovery TXT String
        const recoveryString = await generateRecoveryString(vaultJson, pwd);
        const txtBlob = new Blob([recoveryString], { type: 'text/plain' });
        await masterZipWriter.add("3-Recovery_String.txt", new window.zip.BlobReader(txtBlob));

        // --- STEP B: Close and Download the Single Master Bundle ---
        const finalBundleBlob = await masterZipWriter.close();
        downloadFile(finalBundleBlob, bundleName);

        // 3. SUCCESS STATE
        if (isAuto) {
            localStorage.setItem(scopedKey, today);
            showSilentToast("Daily recovery bundle saved.");
        }

        // 4. LOGGING & UI CALLBACK
        await logBackupEvent(fullTs, !isAuto);

        if (onBackup) onBackup();
        else if (onSkip) onSkip();

    } catch (err) {
        if (onSkip) onSkip();
        error("backup.runAdminBackup", "Bundle generation failed: " + err);
        throw err; // Re-throw so doRunBackupUI can catch it and show the error modal
    }
}

export async function logBackupEvent(timestamp, autoRun) {
    const scopedKeyManifest = `${G.userEmail}::${C.BACKUP_MANIFEST_KEY}`;
    let manifest = JSON.parse(localStorage.getItem(scopedKeyManifest) || "[]");
    manifest.push({ timestamp, type: autoRun ? 'auto' : 'manual' });

    // Keep only last 20 entries to prevent local storage bloat
    if (manifest.length > C.MAX_BACKUP_MANIFEST_ENTRIES) {
        warn("backup.logBackupEvent", "Manifest threshold reached. Removing oldest entry.");
        manifest = manifest.slice(-C.MAX_BACKUP_MANIFEST_ENTRIES);
    }
    localStorage.setItem(scopedKeyManifest, JSON.stringify(manifest));

    const scopedKeyCounter = `${G.userEmail}::${C.BACKUP_CLEANUP_COUNTER_KEY}`;
    // THE INCREMENTER (This is what the Pill tracks)
    let counter = parseInt(localStorage.getItem(scopedKeyCounter) || 0);
    counter++;
    localStorage.setItem(scopedKeyCounter, counter);
    log("backup.logBackupEvent", `Event logged. New cleanup count: ${counter}`);
}

function downloadFile(blob, name) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;

    // Add to body briefly (required for some mobile browsers)
    document.body.appendChild(a);
    a.click();

    // Clean up the DOM element immediately
    document.body.removeChild(a);

    // CRITICAL: Delay the memory cleanup (Revoke)
    // 5000ms (5 seconds) is the "Safe Zone" for mobile OS handoffs
    setTimeout(() => {
        URL.revokeObjectURL(url);
        log("backup.downloadFile", "Blob URL revoked successfully.");
    }, 5000);
}

async function generateRecoveryHTML(json, password) {
    // 1. Generate unique Salt and IV for this specific HTML file
    const salt = CR.randomBytes(CR.CR_ALG.SALT_LENGTH);
    const iv = CR.randomBytes(CR.CR_ALG.AES_GCM_IV_LENGTH);

    // 2. Derive Key using your crypto.js standard
    const key = await CR.deriveKey(password, {
        salt: CR.bufToB64(salt),
        iterations: CR.CR_ALG.PBKDF2_ITERATIONS
    });

    // 3. Encrypt the JSON data
    // We use the raw SubtleCrypto here to get the ArrayBuffer for the template
    const encoder = new TextEncoder();
    const encryptedContent = await window.crypto.subtle.encrypt(
        { name: CR.CR_ALG.AES.GCM, iv },
        key,
        encoder.encode(json)
    );

    // 4. Convert to Base64 using your ROBUST chunking logic
    const b64Data = CR.bufToB64(new Uint8Array(encryptedContent));
    const b64Salt = CR.bufToB64(salt);
    const b64Iv = CR.bufToB64(iv);

    // 5. The Standalone HTML Template with EMBEDDED Robust Helpers
    const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Access4 Recovery</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; padding-top: 50px; background: #f0f2f5; color: #333; }
        .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 90%; max-width: 500px; text-align: center; }
        h2 { margin-top: 0; color: #1a73e8; }
        input { width: 100%; padding: 12px; margin: 20px 0; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; font-size: 16px; }
        button { background: #1a73e8; color: white; border: none; padding: 14px 24px; border-radius: 6px; cursor: pointer; width: 100%; font-weight: bold; font-size: 16px; }
        button:hover { background: #1557b0; }
        #msg { margin-top: 15px; font-size: 14px; min-height: 20px; }
        pre { text-align: left; background: #f8f9fa; padding: 15px; overflow-x: auto; display: none; margin-top: 20px; border-radius: 4px; border: 1px solid #ddd; font-size: 12px; max-height: 400px; }
        .instructions { font-size: 12px; color: #666; margin-top: 20px; border-top: 1px solid #eee; padding-top: 10px; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Access4 Vault Recovery</h2>
        <p>This is a standalone recovery file. Enter your master password to decrypt the local data.</p>
        <input type="password" id="pw" placeholder="Master Password">
        <button id="unlockBtn" onclick="decrypt()">Unlock Vault</button>
        <div id="msg"></div>
        <pre id="out"></pre>
        <div class="instructions">
            <b>iPhone/iPad Users:</b> If the button doesn't work, tap the Share icon and select "Open in Safari".
        </div>
    </div>

    <script>
        const dataB64 = "${b64Data}";
        const saltB64 = "${b64Salt}";
        const ivB64 = "${b64Iv}";
        const ITERATIONS = ${CR.CR_ALG.PBKDF2_ITERATIONS};

        // --- EMBEDDED ROBUST HELPERS (Matched to crypto.js) ---
        function b64ToBuf(b64) {
            const binary = atob(b64);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return bytes;
        }

        function bufToB64(input) {
            const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
            let binary = "";
            const chunkSize = 0x8000;
            for (let i = 0; i < bytes.length; i += chunkSize) {
                binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
            }
            return btoa(binary);
        }

        async function decrypt() {
            const msg = document.getElementById('msg');
            const out = document.getElementById('out');
            const btn = document.getElementById('unlockBtn');

            try {
                btn.disabled = true;
                msg.innerText = "Decrypting...";
                msg.style.color = "#666";

                const pass = document.getElementById('pw').value;
                const encoder = new TextEncoder();
                const decoder = new TextDecoder();

                // 1. Re-derive Key (PBKDF2)
                const baseKey = await crypto.subtle.importKey(
                    "raw", encoder.encode(pass), "PBKDF2", false, ["deriveKey"]
                );
                const key = await crypto.subtle.deriveKey(
                    { name: "PBKDF2", salt: b64ToBuf(saltB64), iterations: ITERATIONS, hash: "SHA-256" },
                    baseKey,
                    { name: "AES-GCM", length: 256 },
                    false,
                    ["decrypt"]
                );

                // 2. Decrypt
                const decrypted = await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: b64ToBuf(ivB64) },
                    key,
                    b64ToBuf(dataB64)
                );

                out.innerText = decoder.decode(decrypted);
                out.style.display = 'block';
                msg.innerText = "Success! Data unlocked below.";
                msg.style.color = "green";
            } catch (e) {
                console.error(e);
                msg.innerText = "Error: Decryption failed. Incorrect password?";
                msg.style.color = "red";
                btn.disabled = false;
            }
        }
    </script>
</body>
</html>`;

    return new Blob([html], { type: 'text/html' });
}

/**
 * Creates a single, portable string containing all encrypted vault data.
 * Format: ACCESS4-RECOVERY-v1:Base64Salt:Base64Iv:Base64Data
 */
async function generateRecoveryString(vaultJson, password) {
    // 1. Generate Salt and IV using your established lengths
    const salt = CR.randomBytes(CR.CR_ALG.SALT_LENGTH);

    // 2. Derive the key using your standard PBKDF2 logic
    // We pass a mock 'kdf' object to match your deriveKey signature
    const key = await CR.deriveKey(password, {
        salt: CR.bufToB64(salt),
        iterations: CR.CR_ALG.PBKDF2_ITERATIONS
    });

    // 3. Encrypt using your standard AES-GCM logic
    // Your CR.encrypt returns { iv: b64, data: b64 }
    const encrypted = await CR.encrypt(vaultJson, key);

    // 4. Assemble the final string using your robust bufToB64
    const b64Salt = CR.bufToB64(salt);

    // We return the same format, but built with your safer helpers
    return `${RECOVERY_STRING_PREFIX}:${b64Salt}:${encrypted.iv}:${encrypted.data}`;
}

/**
 * Decrypts a raw Access4 Recovery String
 * @param {string} rawString - The full recovery string
 * @param {string} password - The user's master password
 */
export async function restoreFromRawString(rawString, password) {
    log("backup.restoreFromRawString", "called");

    // 1. DEEP CLEAN: Remove BOM, Zero-width spaces, and Non-Printables
    const cleaned = rawString
        .replace(/^\uFEFF/, '')         // Remove BOM
        .replace(/[^\x20-\x7E:]/g, '')  // Remove everything except standard ASCII and colons
        .replace(/\s/g, '')             // Remove ALL whitespace (spaces, tabs, newlines)
        .trim();

    const parts = cleaned.split(':');

    if (parts.length !== 4 || parts[0].toLowerCase() !== RECOVERY_STRING_PREFIX.toLowerCase()) {
        const msg = `Format check failed. Parts: ${parts.length}, Prefix: ${parts[0]}`;
        error("backup.restoreFromRawString", msg);
        throw new Error(msg);
    }

    try {
        // 1. Re-derive key using your CR logic
        const key = await CR.deriveKey(password, {
            salt: parts[1], // Already B64
            iterations: CR.CR_ALG.PBKDF2_ITERATIONS
        });

        // 2. Decrypt using your CR logic
        // We reconstruct the object your CR.decrypt expects
        const decryptedBuffer = await CR.decrypt({
            iv: parts[2],
            data: parts[3]
        }, key);

        return JSON.parse(new TextDecoder().decode(decryptedBuffer));
    } catch (e) {
        error("backup.restoreFromRawString", "Crypto operation failed", e);
        throw new Error("Decryption succeeded, but data is not valid JSON. The backup may be corrupted.");
    }
}
