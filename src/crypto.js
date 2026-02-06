// vim: ts=4:sw=4

import nodeCrypto from 'crypto';
import assert from 'assert';
import { hkdf } from 'whatsapp-rust-bridge';


function assertBuffer(value) {
    if (!(value instanceof Buffer)) {
        throw TypeError(`Expected Buffer instead of: ${value.constructor.name}`);
    }
    return value;
}


export function encrypt(key, data, iv) {
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}


export function decrypt(key, data, iv) {
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const decipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([decipher.update(data), decipher.final()]);
}


export function calculateMAC(key, data) {
    assertBuffer(key);
    assertBuffer(data);
    const hmac = nodeCrypto.createHmac('sha256', key);
    hmac.update(data);
    return Buffer.from(hmac.digest());
}


export function hash(data) {
    assertBuffer(data);
    const sha512 = nodeCrypto.createHash('sha512');
    sha512.update(data);
    return sha512.digest();
}


// Salts always end up being 32 bytes
export function deriveSecrets(input, salt, info, chunks) {
    // Specific implementation of RFC 5869 that only returns the first 3 32-byte chunks
    assertBuffer(input);
    assertBuffer(salt);
    assertBuffer(info);
    if (salt.byteLength != 32) {
        throw new Error("Got salt of incorrect length");
    }
    chunks = chunks || 3;
    assert(chunks >= 1 && chunks <= 3);

    const result = hkdf(input, chunks * 32, { salt, info: info.toString('utf8') });
    return Array.from({ length: chunks }, (_, i) =>
        Buffer.from(result.slice(i * 32, (i + 1) * 32))
    );
}

export function verifyMAC(data, key, mac, length) {
    const calculatedMac = calculateMAC(key, data).slice(0, length);
    if (mac.length !== length || calculatedMac.length !== length) {
        throw new Error("Bad MAC length");
    }
    if (!mac.equals(calculatedMac)) {
        throw new Error("Bad MAC");
    }
}
