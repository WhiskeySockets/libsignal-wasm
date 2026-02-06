import {
    generateKeyPair,
    generatePreKey as wasmGeneratePreKey,
    generateSignedPreKey as wasmGenerateSignedPreKey,
    generateRegistrationId as wasmGenerateRegistrationId,
} from 'whatsapp-rust-bridge';

export function generateIdentityKeyPair() {
    const kp = generateKeyPair();
    return { pubKey: Buffer.from(kp.pubKey), privKey: Buffer.from(kp.privKey) };
}

export function generateRegistrationId() {
    return wasmGenerateRegistrationId();
}

export function generateSignedPreKey(identityKeyPair, signedKeyId) {
    const spk = wasmGenerateSignedPreKey(identityKeyPair, signedKeyId);
    return {
        keyId: spk.keyId,
        keyPair: {
            pubKey: Buffer.from(spk.keyPair.pubKey),
            privKey: Buffer.from(spk.keyPair.privKey),
        },
        signature: Buffer.from(spk.signature),
    };
}

export function generatePreKey(keyId) {
    const pk = wasmGeneratePreKey(keyId);
    return {
        keyId: pk.keyId,
        keyPair: {
            pubKey: Buffer.from(pk.keyPair.pubKey),
            privKey: Buffer.from(pk.keyPair.privKey),
        },
    };
}
