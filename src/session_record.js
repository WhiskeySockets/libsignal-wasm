import { SessionRecord as WasmSessionRecord } from 'whatsapp-rust-bridge';

class SessionRecord {

    constructor(wasmRecord) {
        if (wasmRecord != null) {
            this._wasmRecord = wasmRecord;
        } else {
            // Create empty record (no open sessions)
            this._wasmRecord = WasmSessionRecord.deserialize(new Uint8Array(0));
        }
    }

    static deserialize(data) {
        return new SessionRecord(WasmSessionRecord.deserialize(data));
    }

    serialize() {
        return this._wasmRecord.serialize(); // Uint8Array (protobuf)
    }

    haveOpenSession() {
        return this._wasmRecord.haveOpenSession();
    }
}

export default SessionRecord;
