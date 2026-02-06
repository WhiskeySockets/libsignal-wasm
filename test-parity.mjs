// Parity test: captures expected behavior of the Signal protocol implementation.
// Run BEFORE and AFTER WASM replacement to verify no regressions.

import {
    keyhelper,
    curve,
    ProtocolAddress,
    SessionBuilder,
    SessionCipher,
    SessionRecord,
} from './index.js';

let passed = 0;
let failed = 0;

function assert(condition, msg) {
    if (!condition) {
        failed++;
        console.error(`  FAIL: ${msg}`);
        return false;
    }
    passed++;
    return true;
}

function assertEq(a, b, msg) {
    if (a !== b) {
        failed++;
        console.error(`  FAIL: ${msg} (got ${a}, expected ${b})`);
        return false;
    }
    passed++;
    return true;
}

function assertBuffer(val, msg) {
    return assert(Buffer.isBuffer(val), `${msg} should be a Buffer (got ${val?.constructor?.name})`);
}

function assertBufferLength(val, len, msg) {
    assertBuffer(val, msg);
    return assertEq(val.byteLength, len, `${msg} should be ${len} bytes`);
}

// --- In-memory signal storage for testing ---
function createStore() {
    const identityKeyPair = keyhelper.generateIdentityKeyPair();
    const registrationId = keyhelper.generateRegistrationId();
    const sessions = {};
    const preKeys = {};
    const signedPreKeys = {};

    return {
        getOurIdentity: () => identityKeyPair,
        getOurRegistrationId: () => registrationId,
        isTrustedIdentity: () => true,

        loadSession: async (addr) => sessions[addr] || null,
        storeSession: async (addr, record) => { sessions[addr] = record; },

        loadPreKey: async (id) => {
            const pk = preKeys[id];
            return pk ? pk.keyPair : null;
        },
        removePreKey: async (id) => { delete preKeys[id]; },
        storePreKey: async (id, preKey) => { preKeys[id] = preKey; },

        loadSignedPreKey: async (id) => {
            const spk = signedPreKeys[id];
            return spk ? spk.keyPair : null;
        },
        storeSignedPreKey: async (id, signedPreKey) => { signedPreKeys[id] = signedPreKey; },

        // Expose for building bundles
        _identityKeyPair: identityKeyPair,
        _registrationId: registrationId,
        _preKeys: preKeys,
        _signedPreKeys: signedPreKeys,
    };
}

async function buildPreKeyBundle(store) {
    const preKey = keyhelper.generatePreKey(1);
    const signedPreKey = keyhelper.generateSignedPreKey(store._identityKeyPair, 1);

    await store.storePreKey(preKey.keyId, preKey);
    await store.storeSignedPreKey(signedPreKey.keyId, signedPreKey);

    return {
        identityKey: store._identityKeyPair.pubKey,
        registrationId: store._registrationId,
        preKey: {
            keyId: preKey.keyId,
            publicKey: preKey.keyPair.pubKey,
        },
        signedPreKey: {
            keyId: signedPreKey.keyId,
            publicKey: signedPreKey.keyPair.pubKey,
            signature: signedPreKey.signature,
        },
    };
}


async function main() {
    console.log('=== Signal Protocol Parity Tests ===\n');

    // ========================================
    // Test 1: Key generation shapes
    // ========================================
    console.log('Test 1: Key generation');

    const identityKp = keyhelper.generateIdentityKeyPair();
    assertBuffer(identityKp.pubKey, 'identityKeyPair.pubKey');
    assertBuffer(identityKp.privKey, 'identityKeyPair.privKey');
    assertEq(identityKp.pubKey.byteLength, 33, 'identityKeyPair.pubKey should be 33 bytes');
    assertEq(identityKp.privKey.byteLength, 32, 'identityKeyPair.privKey should be 32 bytes');

    const regId = keyhelper.generateRegistrationId();
    assert(typeof regId === 'number', 'registrationId should be a number');
    assert(regId >= 0 && regId <= 0x3fff, 'registrationId should be 14-bit');

    const preKey = keyhelper.generatePreKey(42);
    assertEq(preKey.keyId, 42, 'preKey.keyId');
    assertBuffer(preKey.keyPair.pubKey, 'preKey.keyPair.pubKey');
    assertBuffer(preKey.keyPair.privKey, 'preKey.keyPair.privKey');
    assertEq(preKey.keyPair.pubKey.byteLength, 33, 'preKey pubKey should be 33 bytes');
    assertEq(preKey.keyPair.privKey.byteLength, 32, 'preKey privKey should be 32 bytes');

    const signedPreKey = keyhelper.generateSignedPreKey(identityKp, 7);
    assertEq(signedPreKey.keyId, 7, 'signedPreKey.keyId');
    assertBuffer(signedPreKey.keyPair.pubKey, 'signedPreKey.keyPair.pubKey');
    assertBuffer(signedPreKey.keyPair.privKey, 'signedPreKey.keyPair.privKey');
    assertBuffer(signedPreKey.signature, 'signedPreKey.signature');
    assertEq(signedPreKey.keyPair.pubKey.byteLength, 33, 'signedPreKey pubKey should be 33 bytes');
    assertEq(signedPreKey.keyPair.privKey.byteLength, 32, 'signedPreKey privKey should be 32 bytes');
    assertEq(signedPreKey.signature.byteLength, 64, 'signedPreKey signature should be 64 bytes');

    // Verify signature is actually valid
    const sigValid = curve.verifySignature(identityKp.pubKey, signedPreKey.keyPair.pubKey, signedPreKey.signature);
    assert(sigValid === true, 'signedPreKey signature should be valid');

    console.log('');

    // ========================================
    // Test 2: Session establishment + first encrypt (PreKeyWhisperMessage)
    // ========================================
    console.log('Test 2: Session establishment + first encrypt');

    const aliceStore = createStore();
    const bobStore = createStore();

    const bobAddr = new ProtocolAddress('bob', 1);
    const aliceAddr = new ProtocolAddress('alice', 1);

    const bobBundle = await buildPreKeyBundle(bobStore);

    const aliceBuilder = new SessionBuilder(aliceStore, bobAddr);
    await aliceBuilder.initOutgoing(bobBundle);

    const aliceCipher = new SessionCipher(aliceStore, bobAddr);

    const plaintext1 = Buffer.from('Hello Bob from Alice!');
    const encrypted1 = await aliceCipher.encrypt(plaintext1);

    assertEq(encrypted1.type, 3, 'First encrypt should be PreKeyWhisperMessage (type=3)');
    assertBuffer(encrypted1.body, 'encrypted.body');
    assert(encrypted1.body.byteLength > 0, 'encrypted body should not be empty');

    console.log(`  encrypt() returned: { type: ${encrypted1.type}, body: ${encrypted1.body.constructor.name}[${encrypted1.body.byteLength}] }`);
    console.log('');

    // ========================================
    // Test 3: First decrypt (PreKeyWhisperMessage)
    // ========================================
    console.log('Test 3: First decrypt (PreKeyWhisperMessage)');

    const bobCipher = new SessionCipher(bobStore, aliceAddr);
    const decrypted1 = await bobCipher.decryptPreKeyWhisperMessage(encrypted1.body);

    assertBuffer(decrypted1, 'decryptPreKeyWhisperMessage result');
    assert(decrypted1.equals(plaintext1), 'Decrypted plaintext should match original');
    console.log(`  decryptPreKeyWhisperMessage returned: ${decrypted1.constructor.name}[${decrypted1.byteLength}] = "${decrypted1.toString()}"`);
    console.log('');

    // ========================================
    // Test 4: Normal encrypt after session established (WhisperMessage)
    // ========================================
    console.log('Test 4: Normal encrypt (WhisperMessage) — Bob→Alice');

    const plaintext2 = Buffer.from('Hello Alice from Bob!');
    const encrypted2 = await bobCipher.encrypt(plaintext2);

    assertEq(encrypted2.type, 1, 'Normal encrypt should be WhisperMessage (type=1)');
    assertBuffer(encrypted2.body, 'encrypted2.body');
    console.log(`  encrypt() returned: { type: ${encrypted2.type}, body: ${encrypted2.body.constructor.name}[${encrypted2.body.byteLength}] }`);
    console.log('');

    // ========================================
    // Test 5: Normal decrypt (WhisperMessage)
    // ========================================
    console.log('Test 5: Normal decrypt (WhisperMessage)');

    const decrypted2 = await aliceCipher.decryptWhisperMessage(encrypted2.body);

    assertBuffer(decrypted2, 'decryptWhisperMessage result');
    assert(decrypted2.equals(plaintext2), 'Decrypted plaintext should match original');
    console.log(`  decryptWhisperMessage returned: ${decrypted2.constructor.name}[${decrypted2.byteLength}] = "${decrypted2.toString()}"`);
    console.log('');

    // ========================================
    // Test 6: Bidirectional round-trip (Alice→Bob→Alice)
    // ========================================
    console.log('Test 6: Bidirectional round-trip');

    const msg3 = Buffer.from('Round trip message from Alice');
    const enc3 = await aliceCipher.encrypt(msg3);
    assertEq(enc3.type, 1, 'Alice second encrypt should be WhisperMessage (type=1)');
    const dec3 = await bobCipher.decryptWhisperMessage(enc3.body);
    assert(dec3.equals(msg3), 'Bob should decrypt Alice round-trip message');

    const msg4 = Buffer.from('Round trip reply from Bob');
    const enc4 = await bobCipher.encrypt(msg4);
    assertEq(enc4.type, 1, 'Bob second encrypt should be WhisperMessage (type=1)');
    const dec4 = await aliceCipher.decryptWhisperMessage(enc4.body);
    assert(dec4.equals(msg4), 'Alice should decrypt Bob round-trip reply');

    console.log('');

    // ========================================
    // Test 7: Multiple sequential messages (10+)
    // ========================================
    console.log('Test 7: Multiple sequential messages');

    for (let i = 0; i < 15; i++) {
        const sender = i % 2 === 0 ? aliceCipher : bobCipher;
        const receiver = i % 2 === 0 ? bobCipher : aliceCipher;
        const msg = Buffer.from(`Sequential message #${i}`);
        const enc = await sender.encrypt(msg);
        assertEq(enc.type, 1, `Message #${i} should be WhisperMessage (type=1)`);
        assertBuffer(enc.body, `Message #${i} body`);

        const dec = i % 2 === 0
            ? await receiver.decryptWhisperMessage(enc.body)
            : await receiver.decryptWhisperMessage(enc.body);
        assert(dec.equals(msg), `Message #${i} should decrypt correctly`);
    }
    console.log(`  15 sequential messages sent and decrypted correctly`);
    console.log('');

    // ========================================
    // Test 8: hasOpenSession
    // ========================================
    console.log('Test 8: hasOpenSession');

    const aliceHasSession = await aliceCipher.hasOpenSession();
    assertEq(aliceHasSession, true, 'Alice should have open session');

    const bobHasSession = await bobCipher.hasOpenSession();
    assertEq(bobHasSession, true, 'Bob should have open session');

    // Check no session for unrelated address
    const unknownAddr = new ProtocolAddress('unknown', 1);
    const unknownCipher = new SessionCipher(aliceStore, unknownAddr);
    const unknownHasSession = await unknownCipher.hasOpenSession();
    assertEq(unknownHasSession, false, 'Unknown address should NOT have open session');

    console.log('');

    // ========================================
    // Test 9: SessionRecord serialize/deserialize round-trip
    // ========================================
    console.log('Test 9: SessionRecord serialize/deserialize round-trip');

    const aliceSession = await aliceStore.loadSession(bobAddr.toString());
    assert(aliceSession !== null, 'Alice should have a stored session');

    const serialized = aliceSession.serialize();
    assert(serialized !== null && serialized !== undefined, 'serialize() should return data');
    console.log(`  serialize() returned: ${serialized.constructor.name} (${typeof serialized === 'object' ? (serialized instanceof Uint8Array ? serialized.byteLength + ' bytes' : JSON.stringify(serialized).length + ' chars JSON') : typeof serialized})`);

    const deserialized = SessionRecord.deserialize(serialized);
    assert(deserialized instanceof SessionRecord, 'deserialize() should return SessionRecord');

    const haveOpen = deserialized.haveOpenSession();
    assertEq(haveOpen, true, 'Deserialized record should have open session');

    // Verify can still encrypt/decrypt after deserialize
    await aliceStore.storeSession(bobAddr.toString(), deserialized);
    const aliceCipher2 = new SessionCipher(aliceStore, bobAddr);

    const msgAfterDeserialize = Buffer.from('Message after deserialize');
    const encAfterDeserialize = await aliceCipher2.encrypt(msgAfterDeserialize);
    assertEq(encAfterDeserialize.type, 1, 'Encrypt after deserialize should be type=1');
    const decAfterDeserialize = await bobCipher.decryptWhisperMessage(encAfterDeserialize.body);
    assert(decAfterDeserialize.equals(msgAfterDeserialize), 'Decrypt after deserialize should work');

    console.log('');

    // ========================================
    // Test 10: haveOpenSession on SessionRecord
    // ========================================
    console.log('Test 10: haveOpenSession on SessionRecord');

    const freshRecord = new SessionRecord();
    assertEq(freshRecord.haveOpenSession(), false, 'Fresh SessionRecord should NOT have open session');

    const activeRecord = await aliceStore.loadSession(bobAddr.toString());
    assertEq(activeRecord.haveOpenSession(), true, 'Active SessionRecord should have open session');

    console.log('');

    // ========================================
    // Test 11: Out-of-order messages (send multiple, decrypt in different order)
    // ========================================
    console.log('Test 11: Out-of-order messages');

    const msgs = [];
    for (let i = 0; i < 5; i++) {
        const msg = Buffer.from(`OOO message ${i}`);
        const enc = await aliceCipher2.encrypt(msg);
        msgs.push({ plaintext: msg, encrypted: enc });
    }

    // Decrypt in reverse order
    for (let i = msgs.length - 1; i >= 0; i--) {
        const dec = await bobCipher.decryptWhisperMessage(msgs[i].encrypted.body);
        assert(dec.equals(msgs[i].plaintext), `Out-of-order message #${i} should decrypt correctly`);
    }
    console.log(`  5 out-of-order messages decrypted correctly`);
    console.log('');

    // ========================================
    // Test 12: New session establishment (fresh Alice→fresh Carol)
    // ========================================
    console.log('Test 12: Fresh session establishment');

    const carolStore = createStore();
    const carolAddr = new ProtocolAddress('carol', 1);
    const carolBundle = await buildPreKeyBundle(carolStore);

    const aliceToCarolBuilder = new SessionBuilder(aliceStore, carolAddr);
    await aliceToCarolBuilder.initOutgoing(carolBundle);

    const aliceToCarolCipher = new SessionCipher(aliceStore, carolAddr);
    const carolCipher = new SessionCipher(carolStore, aliceAddr);

    const msgToCarol = Buffer.from('Hello Carol!');
    const encToCarol = await aliceToCarolCipher.encrypt(msgToCarol);
    assertEq(encToCarol.type, 3, 'First message to new recipient should be PreKeyWhisperMessage (type=3)');

    const decFromAlice = await carolCipher.decryptPreKeyWhisperMessage(encToCarol.body);
    assert(decFromAlice.equals(msgToCarol), 'Carol should decrypt Alice message');

    // Second message still type=3 until Carol replies (pendingPreKey not cleared)
    const msg2ToCarol = Buffer.from('Second message to Carol');
    const enc2ToCarol = await aliceToCarolCipher.encrypt(msg2ToCarol);
    assertEq(enc2ToCarol.type, 3, 'Second message still PreKey until reply (type=3)');

    // Carol replies → clears pendingPreKey on next Alice encrypt
    const dec2FromAlice = await carolCipher.decryptPreKeyWhisperMessage(enc2ToCarol.body);
    assert(dec2FromAlice.equals(msg2ToCarol), 'Carol should decrypt second message');

    const carolReply = Buffer.from('Reply from Carol');
    const encCarolReply = await carolCipher.encrypt(carolReply);
    const decCarolReply = await aliceToCarolCipher.decryptWhisperMessage(encCarolReply.body);
    assert(decCarolReply.equals(carolReply), 'Alice should decrypt Carol reply');

    // Now third message should be type=1
    const msg3ToCarol = Buffer.from('Third message to Carol');
    const enc3ToCarol = await aliceToCarolCipher.encrypt(msg3ToCarol);
    assertEq(enc3ToCarol.type, 1, 'Third message after reply should be WhisperMessage (type=1)');

    console.log('');

    // ========================================
    // Summary
    // ========================================
    console.log('=== Results ===');
    console.log(`Passed: ${passed}`);
    console.log(`Failed: ${failed}`);

    if (failed > 0) {
        process.exit(1);
    } else {
        console.log('\nAll parity tests passed!');
    }
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
