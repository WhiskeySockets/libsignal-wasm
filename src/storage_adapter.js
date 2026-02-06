import SessionRecord from './session_record.js';

export function createStorageAdapter(storage) {
    return {
        async loadSession(address) {
            const record = await storage.loadSession(address);
            if (!record) return null;
            // Our SessionRecord wrapper — extract the bytes
            if (record._wasmRecord) return record._wasmRecord.serialize();
            // Raw Uint8Array/Buffer
            if (record instanceof Uint8Array) return record;
            // Legacy JS SessionRecord — pass serialize() result
            if (typeof record.serialize === 'function') {
                const data = record.serialize();
                if (data instanceof Uint8Array) return data;
                return null; // JSON format → force renegotiation
            }
            return null;
        },

        async storeSession(address, wasmSessionRecord) {
            const wrapper = new SessionRecord(wasmSessionRecord);
            await storage.storeSession(address, wrapper);
        },

        getOurIdentity: () => storage.getOurIdentity(),
        getOurRegistrationId: () => storage.getOurRegistrationId(),

        isTrustedIdentity: (name, key, direction) =>
            storage.isTrustedIdentity(name, key, direction),

        async loadPreKey(id) {
            const kp = await storage.loadPreKey(id);
            return kp || null;
        },

        removePreKey: (id) => storage.removePreKey(id),

        async loadSignedPreKey(id) {
            const result = await storage.loadSignedPreKey(id);
            if (!result) return null;
            // Already full format { keyId, keyPair, signature }
            if (result.keyPair) return result;
            // Flat format { privKey, pubKey } → wrap for WASM
            return {
                keyId: typeof id === 'number' ? id : 0,
                keyPair: { pubKey: result.pubKey, privKey: result.privKey },
                signature: new Uint8Array(64),
            };
        },

        async loadSenderKey(keyId) {
            return (await storage.loadSenderKey?.(keyId)) ?? null;
        },

        async storeSenderKey(keyId, record) {
            await storage.storeSenderKey?.(keyId, record);
        },
    };
}
