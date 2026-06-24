#!/usr/bin/env node
// Test AES-CTR decryption with the ACTUAL aes-js library
// and various counter initializations, cross-validated across sessions

var aesjs = require('aes-js');

var KEY = [0xd1,0xea,0x33,0xcc,0x0a,0x91,0xb4,0xe5,0xf9,0x79,0x91,0x00,0x92,0x15,0xd9,0x16];
var CT1 = [0xd8,0x4f,0x13,0xf8,0xac,0x41,0xaf,0x20,0xf0,0x58,0xaf,0xb1,0xdc,0xd6,0x66,0x2d];
var CT3 = [0x52,0xe7,0xe1,0xee,0x10,0x2d,0xc3,0x6e,0x85,0x43,0xad,0x37,0xdf,0xba,0xd6,0x83];

var S1_TX = Buffer.from('a9c565761e40f202763ec300b12c41f2a8430dbd', 'hex');
var S1_RX = Buffer.from('e30c007600000000000000000000000000000000', 'hex');
var S3_TX = Buffer.from('e4d4b6afeb9e4a993abc9d00350e624081d46347', 'hex');
var S3_RX_HDR = Buffer.from('60902e47', 'hex'); // From btsnoop

function testCounter(label, ctrFn1, ctrFn3) {
    try {
        var aes1 = new aesjs.ModeOfOperation.ctr(KEY, ctrFn1());
        var pt1 = aes1.decrypt(CT1);
        var aes3 = new aesjs.ModeOfOperation.ctr(KEY, ctrFn3());
        var pt3 = aes3.decrypt(CT3);

        if (pt1[0] === pt3[0] && pt1[0] !== 0 && pt1[0] !== 0xff) {
            var wt = pt1[0] & 7;
            var fn = pt1[0] >> 3;
            if (wt <= 2 && fn >= 1 && fn <= 20) {
                console.log('MATCH ' + label + ': byte=0x' + pt1[0].toString(16) +
                    ' (field=' + fn + ' wire=' + wt + ')' +
                    ' S1=' + Buffer.from(pt1).toString('hex').substring(0, 16) +
                    ' S3=' + Buffer.from(pt3).toString('hex').substring(0, 16));
            }
        }
    } catch(e) {}
}

// 1. Integer counters 0-10000
console.log('Testing integer counters 0-10000...');
for (var i = 0; i < 10000; i++) {
    testCounter('Counter(' + i + ')',
        function() { return new aesjs.Counter(i); },
        function() { return new aesjs.Counter(i); }
    );
}

// 2. Counter from init headers (various endianness)
console.log('Testing header-derived counters...');
var headerTests = [
    ['rx_BE', S1_RX.readUInt32BE(0), S3_RX_HDR.readUInt32BE(0)],
    ['rx_LE', S1_RX.readUInt32LE(0), S3_RX_HDR.readUInt32LE(0)],
    ['tx_BE_hdr', S1_TX.readUInt32BE(0), S3_TX.readUInt32BE(0)],
    ['tx_LE_hdr', S1_TX.readUInt32LE(0), S3_TX.readUInt32LE(0)],
    ['tx_BE_body', S1_TX.readUInt32BE(4), S3_TX.readUInt32BE(4)],
    ['tx_LE_body', S1_TX.readUInt32LE(4), S3_TX.readUInt32LE(4)],
];

for (var t of headerTests) {
    var v1 = t[1], v3 = t[2];
    testCounter(t[0] + '=' + v1,
        function() { return new aesjs.Counter(v1); },
        function() { return new aesjs.Counter(v3); }
    );
    // Also try with offsets
    for (var off = 0; off < 50; off++) {
        testCounter(t[0] + '+' + off,
            function() { return new aesjs.Counter(v1 + off); },
            function() { return new aesjs.Counter(v3 + off); }
        );
    }
}

// 3. setBytes from init data
console.log('Testing setBytes counters...');
var byteTests = [
    ['tx[4:20]', Array.from(S1_TX.slice(4, 20)), Array.from(S3_TX.slice(4, 20))],
    ['tx[:16]', Array.from(S1_TX.slice(0, 16)), Array.from(S3_TX.slice(0, 16))],
    ['rx[:16]', Array.from(S1_RX.slice(0, 16)), Array.from(Buffer.concat([S3_RX_HDR, Buffer.alloc(12)]))],
    ['zeros', Array(16).fill(0), Array(16).fill(0)],
];

for (var bt of byteTests) {
    var b1 = bt[1], b3 = bt[2];
    testCounter('setBytes(' + bt[0] + ')',
        function() { var c = new aesjs.Counter(1); c.setBytes(b1); return c; },
        function() { var c = new aesjs.Counter(1); c.setBytes(b3); return c; }
    );
}

console.log('Done.');
