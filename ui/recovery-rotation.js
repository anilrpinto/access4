import { C, AU, CR, ID, R, E, RG, GD, log, trace, debug, info, warn, error } from '../exports.js';

import { vaultRecoveryKey, vaultUI } from './loader.js';

function showRecoveryRotationStatusMessage(msg, type = "error") {
    if (!vaultRecoveryKey.statusMsg) return;

    vaultRecoveryKey.statusMsg.textContent = msg;
    vaultRecoveryKey.statusMsg.className = `status-message ${type}`;
}

function doCancelRecoveryRotationClick() {
    log("vaultUI.doCancelRecoveryRotationClick", "called");
    vaultRecoveryKey.mainSection.setVisible(false);
    vaultUI.mainSection.setVisible(true);
}

async function doRotateRecoveryKeyClick(rotateMode) {
    log("vaultUI.doRotateRecoveryKeyClick", "called - Starting recovery key creation in rotateMode:", rotateMode);

    try {

        AU.requireAdmin();

        if (rotateMode) {
            const currPwd = vaultRecoveryKey.currentPwdInput.value;
            if (!currPwd || currPwd.length < C.PASSWORD_MIN_LEN || !(await R.verifyRecoveryPassword(currPwd))) {
                throw new Error("Incorrect current password");
            }
        }

        const pwd = vaultRecoveryKey.pwdInput.value;
        const confirm = vaultRecoveryKey.confirmPwdInput.value;

        if (!pwd || pwd.length < C.PASSWORD_MIN_LEN) {
            throw new Error("Recovery password must be at least 7 characters.");
        }
        if (pwd !== confirm) {
            throw new Error("Recovery passwords do not match.");
        }

        vaultRecoveryKey.currentPwdInput.clear();
        vaultRecoveryKey.pwdInput.clear();
        vaultRecoveryKey.confirmPwdInput.clear();

        vaultRecoveryKey.rotateBtn.setEnabled(false);
        showRecoveryRotationStatusMessage("Creating recovery key please wait...");

        const recoveryIdentity = await ID.createRecoveryIdentity(pwd);

        log("vaultUI.doRotateRecoveryKeyClick", "Private key encrypted with recovery password");

        // 4️⃣ Ensure recovery folder
        const recoveryFolderId = await R.ensureRecoveryFolder();

        // 5️⃣ Write private recovery file
        await GD.upsertJsonFile({ name: C.RECOVERY_KEY_PRIVATE_FILE, parentId: recoveryFolderId, json: recoveryIdentity, overwrite: true });
        log("vaultUI.doRotateRecoveryKeyClick", `${C.RECOVERY_KEY_PRIVATE_FILE} written`);

        // 6️⃣ Write public recovery file (matching device key structure)
        const recoveryPublicJson = {
            type:"recovery",
            role:"recovery",
            keyId: recoveryIdentity.fingerprint,
            fingerprint: recoveryIdentity.fingerprint,
            created: recoveryIdentity.created,
            algorithm: {
                name: CR.CR_ALG.RSA.OAEP,
                modulusLength: CR.CR_ALG.RSA_MODULUS_LENGTH,
                hash: CR.CR_ALG.HASH.SHA256,
                usage: ["encrypt"]
            },
            publicKey: {
                format:"spki",
                encoding:"base64",
                data: recoveryIdentity.publicKey
            }
        };

        await GD.upsertJsonFile({name: C.RECOVERY_KEY_PUBLIC_FILE, parentId: recoveryFolderId, json: recoveryPublicJson, overwrite: true });
        log("vaultUI.doRotateRecoveryKeyClick", `${C.RECOVERY_KEY_PUBLIC_FILE} written`);

        // Refresh registry with newly uploaded recovery public key
        await RG.buildKeyRegistryFromDrive();

        // 7️⃣ Add to envelope for CEK housekeeping
        await E.addRecoveryKeyToEnvelope({
            publicKey: recoveryIdentity.publicKey,
            keyId: recoveryIdentity.fingerprint
        });

        log("vaultUI.doRotateRecoveryKeyClick", "Recovery key successfully established");
        //showRecoveryRotationStatusMessage("Recovery key created!", "status-message success");

        vaultRecoveryKey.rotateBtn.setEnabled(true);
        doCancelRecoveryRotationClick();
        showStatusMessage("Recovery key created!", "status-message success");

    } catch (err) {
        vaultRecoveryKey.rotateBtn.setEnabled(true);
        showRecoveryRotationStatusMessage(err.message || "Recovery setup failed", "status-message error");
    }
}

/**
 * EXPORTED FUNCTIONS
 */
export async function showRecoveryRotationUI() {
    log("vaultUI.showRecoveryRotationUI", "called");

    const rotateMode = await R.hasRecoveryKeyOnDrive();

    vaultRecoveryKey.currentPwdSection.setVisible(rotateMode);
    vaultRecoveryKey.rotateBtn.setText(rotateMode ? "Rotate recovery" : "Create recovery");
    vaultRecoveryKey.mainSection.setVisible(true);
    vaultUI.mainSection.setVisible(false);

    vaultRecoveryKey.rotateBtn.onClick((e) => doRotateRecoveryKeyClick(rotateMode));
    vaultRecoveryKey.cancelBtn.onClick((e) => doCancelRecoveryRotationClick());

    showRecoveryRotationStatusMessage("Create a recovery password. This allows account recovery if all devices are lost.", "status-message");
}
