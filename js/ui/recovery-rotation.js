import { C, AU, CR, ID, R, SV, RG, GD, log, trace, debug, info, warn, error } from '@/shared/exports.js';

import { vaultRecoveryKeyUI, vaultUI } from '@/ui/loader.js';

function showRecoveryRotationStatusMessage(msg, type = "error") {
    if (!vaultRecoveryKeyUI.statusMsg) return;

    vaultRecoveryKeyUI.statusMsg.textContent = msg;
    vaultRecoveryKeyUI.statusMsg.className = `status-message ${type}`;
}

function doCancelRecoveryRotationClick() {
    log("recKeyRotUI.doCancelRecoveryRotationClick", "called");
    vaultRecoveryKeyUI.mainSection.setVisible(false);
    vaultUI.mainSection.setVisible(true);
}

async function doRotateRecoveryKeyClick(rotateMode) {
    log("recKeyRotUI.doRotateRecoveryKeyClick", "called - Starting recovery key creation in rotateMode:", rotateMode);

    try {

        AU.requireAdmin();

        if (rotateMode) {
            const currPwd = vaultRecoveryKeyUI.currentPwdInput.value;
            if (!currPwd || currPwd.length < C.PASSWORD_MIN_LEN || !(await R.verifyRecoveryPassword(currPwd))) {
                throw new Error("Incorrect current password");
            }
        }

        const pwd = vaultRecoveryKeyUI.pwdInput.value;
        const confirm = vaultRecoveryKeyUI.confirmPwdInput.value;

        if (!pwd || pwd.length < C.PASSWORD_MIN_LEN) {
            throw new Error("Recovery password must be at least 7 characters.");
        }
        if (pwd !== confirm) {
            throw new Error("Recovery passwords do not match.");
        }

        vaultRecoveryKeyUI.currentPwdInput.clear();
        vaultRecoveryKeyUI.pwdInput.clear();
        vaultRecoveryKeyUI.confirmPwdInput.clear();

        vaultRecoveryKeyUI.rotateBtn.setEnabled(false);
        showRecoveryRotationStatusMessage("Creating recovery key please wait...");

        const recoveryIdentity = await ID.createRecoveryIdentity(pwd);

        log("recKeyRotUI.doRotateRecoveryKeyClick", "Private key encrypted with recovery password");

        // 4️⃣ Ensure recovery folder
        const recoveryFolderId = await R.ensureRecoveryFolder();

        // 5️⃣ Write private recovery file
        await GD.upsertJsonFile({ name: C.RECOVERY_KEY_PRIVATE_FILE, parentId: recoveryFolderId, json: recoveryIdentity, overwrite: true });
        log("recKeyRotUI.doRotateRecoveryKeyClick", `${C.RECOVERY_KEY_PRIVATE_FILE} written`);

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
        log("recKeyRotUI.doRotateRecoveryKeyClick", `${C.RECOVERY_KEY_PUBLIC_FILE} written`);

        // Refresh registry with newly uploaded recovery public key
        await RG.buildKeyRegistryFromDrive();

        // 7️⃣ Add to envelope for CEK housekeeping
        await SV.addRecoveryKeyToEnvelope({
            publicKey: recoveryIdentity.publicKey,
            keyId: recoveryIdentity.fingerprint
        });

        log("recKeyRotUI.doRotateRecoveryKeyClick", "Recovery key successfully established");
        //showRecoveryRotationStatusMessage("Recovery key created!", "status-message success");

        vaultRecoveryKeyUI.rotateBtn.setEnabled(true);
        doCancelRecoveryRotationClick();
        showStatusMessage("Recovery key created!", "status-message success");

    } catch (err) {
        vaultRecoveryKeyUI.rotateBtn.setEnabled(true);
        showRecoveryRotationStatusMessage(err.message || "Recovery setup failed", "status-message error");
    }
}

/**
 * EXPORTED FUNCTIONS
 */
export async function showRecoveryRotationUI() {
    log("recKeyRotUI.showRecoveryRotationUI", "called");

    const rotateMode = await R.hasRecoveryKeyOnDrive();

    vaultRecoveryKeyUI.currentPwdSection.setVisible(rotateMode);
    vaultRecoveryKeyUI.rotateBtn.setText(rotateMode ? "Rotate recovery" : "Create recovery");
    vaultRecoveryKeyUI.mainSection.setVisible(true);
    vaultUI.mainSection.setVisible(false);

    vaultRecoveryKeyUI.rotateBtn.onClick((e) => doRotateRecoveryKeyClick(rotateMode));
    vaultRecoveryKeyUI.cancelBtn.onClick((e) => doCancelRecoveryRotationClick());

    showRecoveryRotationStatusMessage("Create a recovery password. This allows account recovery if all devices are lost.", "status-message");
}

export function hideRecoveryRotation() {
    vaultRecoveryKeyUI.mainSection.setVisible(false);
}
