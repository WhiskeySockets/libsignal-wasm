import {
    SessionBuilder as WasmSessionBuilder,
    ProtocolAddress as WasmProtocolAddress,
} from 'whatsapp-rust-bridge';
import { createStorageAdapter } from './storage_adapter.js';
import queueJob from './queue_job.js';

class SessionBuilder {

    constructor(storage, protocolAddress) {
        this.addr = protocolAddress;
        const wasmAddr = new WasmProtocolAddress(protocolAddress.id, protocolAddress.deviceId);
        this.builder = new WasmSessionBuilder(createStorageAdapter(storage), wasmAddr);
    }

    async initOutgoing(device) {
        return await queueJob(this.addr.toString(), async () => {
            return await this.builder.processPreKeyBundle(device);
        });
    }
}

export default SessionBuilder;
