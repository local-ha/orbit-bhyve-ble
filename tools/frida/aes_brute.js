#!/usr/bin/env node
// Brute-force AES key derivation using the ACTUAL aes-js library
// Same library the B-Hyve app uses

const aesjs = require('aes-js');
const crypto = require('crypto');

const KEY = Buffer.from('<YOUR_NETWORK_KEY_HEX>', 'hex');
const KEY_B64 = '<YOUR_NETWORK_KEY_BASE64>';

// Session 1
const s1_tx = Buffer.from('a9c565761e40f202763ec300b12c41f2a8430dbd', 'hex');
const s1_rx = Buffer.from('e30c007600000000000000000000000000000000', 'hex');
const s1_ct = Buffer.from('d84f13f8ac41af20f058afb1dcd6662d108ed3096ce055820b85f46a53e87f18946e2208385c', 'hex');

// Session 2 last init
const s2_tx = Buffer.from('b873bb47c57a9f85604bc600fa0323e38ed93bb9', 'hex');
const s2_rx = Buffer.from('60902e4700000000000000000000000000000000', 'hex');
const s2_ct = Buffer.from('5eb0629dc1465d099d9859db7a1b5f2bcb9d2c5c76c328066dc1f1a420e9e1f2b0f7e1f02ca5', 'hex');

function tryDecrypt(key, counterValue, ciphertext, label) {
    try {
        let counter;
        if (Buffer.isBuffer(counterValue) || Array.isArray(counterValue)) {
            counter = new aesjs.Counter(1);
            counter.setBytes(Array.from(counterValue));
        } else {
            counter = new aesjs.Counter(counterValue);
        }

        const aesCtr = new aesjs.ModeOfOperation.ctr(Array.from(key), counter);
        const plaintext = aesCtr.decrypt(Array.from(ciphertext));
        return Buffer.from(plaintext);
    } catch(e) {
        return null;
    }
}

function crc32(buf) {
    // Simple CRC32 implementation
    let crc = 0xFFFFFFFF;
    const table = [];
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        }
        table[i] = c;
    }
    for (let i = 0; i < buf.length; i++) {
        crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xFF];
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

// Key derivation candidates
const keyDerivations = [
    ['networkKey', (tx, rx) => KEY],
    ['SHA256(KEY)', (tx, rx) => crypto.createHash('sha256').update(KEY).digest().subarray(0, 16)],
    ['SHA256(KEY_B64)', (tx, rx) => crypto.createHash('sha256').update(KEY_B64).digest().subarray(0, 16)],
    ['MD5(KEY_B64)', (tx, rx) => crypto.createHash('md5').update(KEY_B64).digest()],
    ['SHA256(KEY+tx)', (tx, rx) => crypto.createHash('sha256').update(Buffer.concat([KEY, tx])).digest().subarray(0, 16)],
    ['SHA256(tx+KEY)', (tx, rx) => crypto.createHash('sha256').update(Buffer.concat([tx, KEY])).digest().subarray(0, 16)],
    // PBKDF2 with simple parameters
    ['PBKDF2(KEY_B64,salt=empty,1)', (tx, rx) => crypto.pbkdf2Sync(KEY_B64, '', 1, 16, 'sha256')],
    ['PBKDF2(KEY_B64,salt=KEY,1)', (tx, rx) => crypto.pbkdf2Sync(KEY_B64, KEY, 1, 16, 'sha256')],
    ['PBKDF2(KEY,salt=b64,1)', (tx, rx) => crypto.pbkdf2Sync(KEY, KEY_B64, 1, 16, 'sha256')],
    ['PBKDF2(KEY_B64,salt=empty,1000)', (tx, rx) => crypto.pbkdf2Sync(KEY_B64, '', 1000, 16, 'sha256')],
    // AES-ECB encrypt/decrypt
    ['AES_E(KEY,tx[:16])', (tx, rx) => { const c = crypto.createCipheriv('aes-128-ecb', KEY, null); c.setAutoPadding(false); return Buffer.concat([c.update(tx.subarray(0,16)), c.final()]); }],
    ['AES_D(KEY,tx[4:20])', (tx, rx) => { const c = crypto.createDecipheriv('aes-128-ecb', KEY, null); c.setAutoPadding(false); return Buffer.concat([c.update(tx.subarray(4,20)), c.final()]); }],
    // XOR
    ['KEY XOR tx[:16]', (tx, rx) => Buffer.from(KEY.map((b, i) => b ^ tx[i]))],
];

// Counter value candidates
const counterDerivations = [
    ['Counter(1)', (tx, rx) => 1],
    ['Counter(0)', (tx, rx) => 0],
    ['setBytes(tx[4:20])', (tx, rx) => tx.subarray(4, 20)],
    ['setBytes(rx[:16])', (tx, rx) => rx.subarray(0, 16)],
    ['setBytes(tx[:16])', (tx, rx) => tx.subarray(0, 16)],
    ['Counter(rx_BE)', (tx, rx) => rx.readUInt32BE(0)],
    ['Counter(rx_LE)', (tx, rx) => rx.readUInt32LE(0)],
    ['Counter(tx_BE)', (tx, rx) => tx.readUInt32BE(0)],
    ['Counter(tx_LE)', (tx, rx) => tx.readUInt32LE(0)],
    ['setBytes(zeros12+rx[:4])', (tx, rx) => Buffer.concat([Buffer.alloc(12), rx.subarray(0,4)])],
    ['setBytes(zeros12+tx[:4])', (tx, rx) => Buffer.concat([Buffer.alloc(12), tx.subarray(0,4)])],
    ['setBytes(rx[:4]+zeros12)', (tx, rx) => Buffer.concat([rx.subarray(0,4), Buffer.alloc(12)])],
    ['setBytes(tx[:4]+zeros12)', (tx, rx) => Buffer.concat([tx.subarray(0,4), Buffer.alloc(12)])],
    ['setBytes(tx[:4]+rx[:4]+zeros8)', (tx, rx) => Buffer.concat([tx.subarray(0,4), rx.subarray(0,4), Buffer.alloc(8)])],
    ['setBytes(AES_E(KEY,rx[:16]))', (tx, rx) => { const c = crypto.createCipheriv('aes-128-ecb', KEY, null); c.setAutoPadding(false); return Buffer.concat([c.update(rx.subarray(0,16)), c.final()]); }],
    ['setBytes(AES_D(KEY,tx[4:20]))', (tx, rx) => { const c = crypto.createDecipheriv('aes-128-ecb', KEY, null); c.setAutoPadding(false); return Buffer.concat([c.update(tx.subarray(4,20)), c.final()]); }],
];

console.log(`Testing ${keyDerivations.length} keys × ${counterDerivations.length} counters = ${keyDerivations.length * counterDerivations.length} combinations`);
console.log();

let found = false;

for (const [kName, kFn] of keyDerivations) {
    for (const [cName, cFn] of counterDerivations) {
        try {
            const k1 = kFn(s1_tx, s1_rx);
            const c1 = cFn(s1_tx, s1_rx);
            const pt1 = tryDecrypt(k1, c1, s1_ct, `${kName}/${cName}`);
            if (!pt1) continue;

            // CRC32 check: last 4 bytes = CRC32 of preceding bytes
            for (let skip = 0; skip < 5; skip++) {
                const body = pt1.subarray(skip, pt1.length - 4);
                const tail = pt1.readUInt32LE(pt1.length - 4);
                const expectedCrc = crc32(body);

                if (tail === expectedCrc) {
                    console.log(`*** CRC32 MATCH! key=${kName} counter=${cName} skip=${skip}`);
                    console.log(`    plaintext: ${pt1.toString('hex')}`);

                    // Verify on session 2
                    const k2 = kFn(s2_tx, s2_rx);
                    const c2 = cFn(s2_tx, s2_rx);
                    const pt2 = tryDecrypt(k2, c2, s2_ct, 'S2');
                    if (pt2) {
                        const body2 = pt2.subarray(skip, pt2.length - 4);
                        const tail2 = pt2.readUInt32LE(pt2.length - 4);
                        const crc2 = crc32(body2);
                        if (tail2 === crc2) {
                            console.log(`    *** ALSO S2 CRC32 MATCH! ***`);
                            console.log(`    S2 plaintext: ${pt2.toString('hex')}`);
                        }
                    }
                    found = true;
                }
            }

            // Also check first byte match across sessions
            const k2 = kFn(s2_tx, s2_rx);
            const c2 = cFn(s2_tx, s2_rx);
            const pt2 = tryDecrypt(k2, c2, s2_ct.subarray(0, 16), 'S2');
            if (pt2 && pt1[0] === pt2[0] && pt1[0] !== 0 && pt1[0] !== 0xff) {
                // Check if first byte could be protobuf
                const wireType = pt1[0] & 0x07;
                const fieldNum = pt1[0] >> 3;
                if (wireType <= 2 && fieldNum >= 1 && fieldNum <= 15) {
                    console.log(`SAME protobuf byte 0x${pt1[0].toString(16).padStart(2,'0')} (field=${fieldNum} wire=${wireType}): key=${kName} counter=${cName}`);
                    console.log(`  S1: ${pt1.subarray(0,16).toString('hex')}`);
                    console.log(`  S2: ${pt2.toString('hex')}`);
                }
            }
        } catch(e) {
            // Skip errors
        }
    }
}

if (!found) {
    console.log('No CRC32 matches found.');
}
