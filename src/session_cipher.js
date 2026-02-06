import {
    SessionCipher as WasmSessionCipher,
    ProtocolAddress as WasmProtocolAddress,
} from 'whatsapp-rust-bridge';
import ProtocolAddress from './protocol_address.js';
import { createStorageAdapter } from './storage_adapter.js';

class SessionCipher {

    constructor(storage, protocolAddress) {
        if (!(protocolAddress instanceof ProtocolAddress)) {
            throw new TypeError("protocolAddress must be a ProtocolAddress");
        }
        this.addr = protocolAddress;
        this.storage = storage;
        const wasmAddr = new WasmProtocolAddress(protocolAddress.id, protocolAddress.deviceId);
        this.cipher = new WasmSessionCipher(createStorageAdapter(storage), wasmAddr);
    }

    async encrypt(data) {
        const result = await this.cipher.encrypt(data);
        return {
            type: result.type === 2 ? 1 : result.type, // 2→1 for compat
            body: Buffer.from(result.body),
        };
    }

    async decryptWhisperMessage(data) {
        return Buffer.from(await this.cipher.decryptWhisperMessage(data));
    }

    async decryptPreKeyWhisperMessage(data) {
        return Buffer.from(await this.cipher.decryptPreKeyWhisperMessage(data));
    }

    async hasOpenSession() {
        return await this.cipher.hasOpenSession();
    }

    async closeOpenSession() {
        await this.storage.storeSession(this.addr.toString(), null);
    }
}

export default SessionCipher;
