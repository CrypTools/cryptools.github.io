// Aes
/**************************************
 *
 * Go see encrypt.js or decrypt.js
 * This file has been coded using the implementation: http://www.movable-type.co.uk/scripts/aes.html
 *
 **************************************/
class Aes {

    /**
     * AES Cipher function: encrypt 'input' state with algorithm [§5.1];
     *   applies Nr rounds (10/12/14) using key schedule w for 'add round key' stage.
     *
     * @param   {number[]}   input - 16-byte (128-bit) input state array.
     * @param   {number[][]} w - Key schedule as 2D byte-array (Nr+1 × Nb bytes).
     * @returns {number[]}   Encrypted output state array.
     */
    static cipher(input, w) {
        const Nb = 4; // block size (in words): no of columns in state (fixed at 4 for AES)
        const Nr = w.length / Nb - 1; // no of rounds: 10/12/14 for 128/192/256-bit keys

        let state = [
            [],
            [],
            [],
            []
        ]; // initialise 4×Nb byte-array 'state' with input [§3.4]
        for (let i = 0; i < 4 * Nb; i++) state[i % 4][Math.floor(i / 4)] = input[i];

        state = Aes.addRoundKey(state, w, 0, Nb);

        for (let round = 1; round < Nr; round++) {
            state = Aes.subBytes(state, Nb);
            state = Aes.shiftRows(state, Nb);
            state = Aes.mixColumns(state, Nb);
            state = Aes.addRoundKey(state, w, round, Nb);
        }

        state = Aes.subBytes(state, Nb);
        state = Aes.shiftRows(state, Nb);
        state = Aes.addRoundKey(state, w, Nr, Nb);

        const output = new Array(4 * Nb); // convert state to 1-d array before returning [§3.4]
        for (let i = 0; i < 4 * Nb; i++) output[i] = state[i % 4][Math.floor(i / 4)];

        return output;
    }


    /**
     * Perform key expansion to generate a key schedule from a cipher key [§5.2].
     *
     * @param   {number[]}   key - Cipher key as 16/24/32-byte array.
     * @returns {number[][]} Expanded key schedule as 2D byte-array (Nr+1 × Nb bytes).
     */
    static keyExpansion(key) {
        const Nb = 4; // block size (in words): no of columns in state (fixed at 4 for AES)
        const Nk = key.length / 4; // key length (in words): 4/6/8 for 128/192/256-bit keys
        const Nr = Nk + 6; // no of rounds: 10/12/14 for 128/192/256-bit keys

        const w = new Array(Nb * (Nr + 1));
        let temp = new Array(4);

        // initialise first Nk words of expanded key with cipher key
        for (let i = 0; i < Nk; i++) {
            const r = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
            w[i] = r;
        }

        // expand the key into the remainder of the schedule
        for (let i = Nk; i < (Nb * (Nr + 1)); i++) {
            w[i] = new Array(4);
            for (let t = 0; t < 4; t++) temp[t] = w[i - 1][t];
            // each Nk'th word has extra transformation
            if (i % Nk == 0) {
                temp = Aes.subWord(Aes.rotWord(temp));
                for (let t = 0; t < 4; t++) temp[t] ^= Aes.rCon[i / Nk][t];
            }
            // 256-bit key has subWord applied every 4th word
            else if (Nk > 6 && i % Nk == 4) {
                temp = Aes.subWord(temp);
            }
            // xor w[i] with w[i-1] and w[i-Nk]
            for (let t = 0; t < 4; t++) w[i][t] = w[i - Nk][t] ^ temp[t];
        }

        return w;
    }


    /**
     * Apply SBox to state S [§5.1.1].
     *
     * @private
     */
    static subBytes(s, Nb) {
        for (let r = 0; r < 4; r++) {
            for (let c = 0; c < Nb; c++) s[r][c] = Aes.sBox[s[r][c]];
        }
        return s;
    }


    /**
     * Shift row r of state S left by r bytes [§5.1.2].
     *
     * @private
     */
    static shiftRows(s, Nb) {
        const t = new Array(4);
        for (let r = 1; r < 4; r++) {
            for (let c = 0; c < 4; c++) t[c] = s[r][(c + r) % Nb]; // shift into temp copy
            for (let c = 0; c < 4; c++) s[r][c] = t[c]; // and copy back
        } // note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):
        return s;
    }


    /**
     * Combine bytes of each col of state S [§5.1.3].
     *
     * @private
     */
    static mixColumns(s, Nb) {
        for (let c = 0; c < Nb; c++) {
            const a = new Array(Nb); // 'a' is a copy of the current column from 's'
            const b = new Array(Nb); // 'b' is a•{02} in GF(2^8)
            for (let r = 0; r < 4; r++) {
                a[r] = s[r][c];
                b[r] = s[r][c] & 0x80 ? s[r][c] << 1 ^ 0x011b : s[r][c] << 1;
            }
            // a[n] ^ b[n] is a•{03} in GF(2^8)
            s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]; // {02}•a0 + {03}•a1 + a2 + a3
            s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]; // a0 • {02}•a1 + {03}•a2 + a3
            s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]; // a0 + a1 + {02}•a2 + {03}•a3
            s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]; // {03}•a0 + a1 + a2 + {02}•a3
        }
        return s;
    }


    /**
     * Xor Round Key into state S [§5.1.4].
     *
     * @private
     */
    static addRoundKey(state, w, rnd, Nb) {
        for (let r = 0; r < 4; r++) {
            for (let c = 0; c < Nb; c++) state[r][c] ^= w[rnd * 4 + c][r];
        }
        return state;
    }


    /**
     * Apply SBox to 4-byte word w.
     *
     * @private
     */
    static subWord(w) {
        for (let i = 0; i < 4; i++) w[i] = Aes.sBox[w[i]];
        return w;
    }


    /**
     * Rotate 4-byte word w left by one byte.
     *
     * @private
     */
    static rotWord(w) {
        const tmp = w[0];
        for (let i = 0; i < 3; i++) w[i] = w[i + 1];
        w[3] = tmp;
        return w;
    }


}


// sBox is pre-computed multiplicative inverse in GF(2^8) used in subBytes and keyExpansion [§5.1.1]
Aes.sBox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];


// rCon is Round Constant used for the Key Expansion [1st col is 2^(r-1) in GF(2^8)] [§5.2]
Aes.rCon = [
    [0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
];
class AesCtr extends Aes {

    /**
     * Encrypt a text using AES encryption in Counter mode of operation.
     *
     * Unicode multi-byte character safe
     *
     * @param   {string} plaintext - Source text to be encrypted.
     * @param   {string} password - The password to use to generate a key for encryption.
     * @param   {number} nBits - Number of bits to be used in the key; 128 / 192 / 256.
     * @returns {string} Encrypted text.
     *
     * @example
     *   const encr = AesCtr.encrypt('big secret', 'pāşšŵōřđ', 256); // 'lwGl66VVwVObKIr6of8HVqJr'
     */
    static encrypt(plaintext, password, nBits) {
        const blockSize = 16; // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
        if (!(nBits == 128 || nBits == 192 || nBits == 256)) throw new Error('Key size is not 128 / 192 / 256');
        plaintext = AesCtr.utf8Encode(String(plaintext));
        password = AesCtr.utf8Encode(String(password));

        // use AES itself to encrypt password to get cipher key (using plain password as source for key
        // expansion) to give us well encrypted key (in real use hashed password could be used for key)
        const nBytes = nBits / 8; // no bytes in key (16/24/32)
        const pwBytes = new Array(nBytes);
        for (let i = 0; i < nBytes; i++) { // use 1st 16/24/32 chars of password for key
            pwBytes[i] = i < password.length ? password.charCodeAt(i) : 0;
        }
        let key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes)); // gives us 16-byte key
        key = key.concat(key.slice(0, nBytes - 16)); // expand key to 16/24/32 bytes long

        // initialise 1st 8 bytes of counter block with nonce (NIST SP800-38A §B.2): [0-1] = millisec,
        // [2-3] = random, [4-7] = seconds, together giving full sub-millisec uniqueness up to Feb 2106
        const counterBlock = new Array(blockSize);

        const nonce = (new Date()).getTime(); // timestamp: milliseconds since 1-Jan-1970
        const nonceMs = nonce % 1000;
        const nonceSec = Math.floor(nonce / 1000);
        const nonceRnd = Math.floor(Math.random() * 0xffff);
        // for debugging: nonce = nonceMs = nonceSec = nonceRnd = 0;

        for (let i = 0; i < 2; i++) counterBlock[i] = (nonceMs >>> i * 8) & 0xff;
        for (let i = 0; i < 2; i++) counterBlock[i + 2] = (nonceRnd >>> i * 8) & 0xff;
        for (let i = 0; i < 4; i++) counterBlock[i + 4] = (nonceSec >>> i * 8) & 0xff;

        // and convert it to a string to go on the front of the ciphertext
        let ctrTxt = '';
        for (let i = 0; i < 8; i++) ctrTxt += String.fromCharCode(counterBlock[i]);

        // generate key schedule - an expansion of the key into distinct Key Rounds for each round
        const keySchedule = Aes.keyExpansion(key);

        const blockCount = Math.ceil(plaintext.length / blockSize);
        let ciphertext = '';

        for (let b = 0; b < blockCount; b++) {
            // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
            // done in two stages for 32-bit ops: using two words allows us to go past 2^32 blocks (68GB)
            for (let c = 0; c < 4; c++) counterBlock[15 - c] = (b >>> c * 8) & 0xff;
            for (let c = 0; c < 4; c++) counterBlock[15 - c - 4] = (b / 0x100000000 >>> c * 8);

            const cipherCntr = Aes.cipher(counterBlock, keySchedule); // -- encrypt counter block --

            // block size is reduced on final block
            const blockLength = b < blockCount - 1 ? blockSize : (plaintext.length - 1) % blockSize + 1;
            const cipherChar = new Array(blockLength);

            for (let i = 0; i < blockLength; i++) {
                // -- xor plaintext with ciphered counter char-by-char --
                cipherChar[i] = cipherCntr[i] ^ plaintext.charCodeAt(b * blockSize + i);
                cipherChar[i] = String.fromCharCode(cipherChar[i]);
            }
            ciphertext += cipherChar.join('');

            // if within web worker, announce progress every 1000 blocks (roughly every 50ms)
            if (typeof WorkerGlobalScope != 'undefined' && self instanceof WorkerGlobalScope) {
                if (b % 1000 == 0) self.postMessage({
                    progress: b / blockCount
                });
            }
        }

        ciphertext = AesCtr.base64Encode(ctrTxt + ciphertext);

        return ciphertext;
    }


    /**
     * Decrypt a text encrypted by AES in counter mode of operation
     *
     * @param   {string} ciphertext - Cipher text to be decrypted.
     * @param   {string} password - Password to use to generate a key for decryption.
     * @param   {number} nBits - Number of bits to be used in the key; 128 / 192 / 256.
     * @returns {string} Decrypted text
     *
     * @example
     *   const decr = AesCtr.decrypt('lwGl66VVwVObKIr6of8HVqJr', 'pāşšŵōřđ', 256); // 'big secret'
     */
    static decrypt(ciphertext, password, nBits) {
        const blockSize = 16; // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
        if (!(nBits == 128 || nBits == 192 || nBits == 256)) throw new Error('Key size is not 128 / 192 / 256');
        ciphertext = AesCtr.base64Decode(String(ciphertext));
        password = AesCtr.utf8Encode(String(password));

        // use AES to encrypt password (mirroring encrypt routine)
        const nBytes = nBits / 8; // no bytes in key
        const pwBytes = new Array(nBytes);
        for (let i = 0; i < nBytes; i++) { // use 1st nBytes chars of password for key
            pwBytes[i] = i < password.length ? password.charCodeAt(i) : 0;
        }
        let key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes));
        key = key.concat(key.slice(0, nBytes - 16)); // expand key to 16/24/32 bytes long

        // recover nonce from 1st 8 bytes of ciphertext
        const counterBlock = new Array(8);
        const ctrTxt = ciphertext.slice(0, 8);
        for (let i = 0; i < 8; i++) counterBlock[i] = ctrTxt.charCodeAt(i);

        // generate key schedule
        const keySchedule = Aes.keyExpansion(key);

        // separate ciphertext into blocks (skipping past initial 8 bytes)
        const nBlocks = Math.ceil((ciphertext.length - 8) / blockSize);
        const ct = new Array(nBlocks);
        for (let b = 0; b < nBlocks; b++) ct[b] = ciphertext.slice(8 + b * blockSize, 8 + b * blockSize + blockSize);
        ciphertext = ct; // ciphertext is now array of block-length strings

        // plaintext will get generated block-by-block into array of block-length strings
        let plaintext = '';

        for (let b = 0; b < nBlocks; b++) {
            // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
            for (let c = 0; c < 4; c++) counterBlock[15 - c] = ((b) >>> c * 8) & 0xff;
            for (let c = 0; c < 4; c++) counterBlock[15 - c - 4] = (((b + 1) / 0x100000000 - 1) >>> c * 8) & 0xff;

            const cipherCntr = Aes.cipher(counterBlock, keySchedule); // encrypt counter block

            const plaintxtByte = new Array(ciphertext[b].length);
            for (let i = 0; i < ciphertext[b].length; i++) {
                // -- xor plaintext with ciphered counter byte-by-byte --
                plaintxtByte[i] = cipherCntr[i] ^ ciphertext[b].charCodeAt(i);
                plaintxtByte[i] = String.fromCharCode(plaintxtByte[i]);
            }
            plaintext += plaintxtByte.join('');

            // if within web worker, announce progress every 1000 blocks (roughly every 50ms)
            if (typeof WorkerGlobalScope != 'undefined' && self instanceof WorkerGlobalScope) {
                if (b % 1000 == 0) self.postMessage({
                    progress: b / nBlocks
                });
            }
        }

        plaintext = AesCtr.utf8Decode(plaintext); // decode from UTF8 back to Unicode multi-byte chars

        return plaintext;
    }


    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */


    /**
     * Encodes multi-byte string to utf8.
     *
     * Note utf8Encode is an identity function with 7-bit ascii strings, but not with 8-bit strings;
     * utf8Encode('x') = 'x', but utf8Encode('ça') = 'Ã§a', and utf8Encode('Ã§a') = 'ÃÂ§a'.
     */
    static utf8Encode(str) {
        try {
            return new TextEncoder().encode(str, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');
        } catch (e) { // no TextEncoder available?
            return unescape(encodeURIComponent(str)); // monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
        }
    }

    /**
     * Decodes utf8 string to multi-byte.
     */
    static utf8Decode(str) {
        try {
            return new TextEncoder().decode(str, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');
        } catch (e) { // no TextEncoder available?
            return decodeURIComponent(escape(str)); // monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
        }
    }

    /*
     * Encodes string as base-64.
     *
     * - developer.mozilla.org/en-US/docs/Web/API/window.btoa, nodejs.org/api/buffer.html
     * - note: btoa & Buffer/binary work on single-byte Unicode (C0/C1), so ok for utf8 strings, not for general Unicode...
     * - note: if btoa()/atob() are not available (eg IE9-), try github.com/davidchambers/Base64.js
     */
    static base64Encode(str) {
        if (typeof btoa != 'undefined') return btoa(str); // browser
        if (typeof Buffer != 'undefined') return new Buffer(str, 'binary').toString('base64'); // Node.js
        throw new Error('No Base64 Encode');
    }

    /*
     * Decodes base-64 encoded string.
     */
    static base64Decode(str) {
        if (typeof atob != 'undefined') return atob(str); // browser
        if (typeof Buffer != 'undefined') return new Buffer(str, 'base64').toString('binary'); // Node.js
        throw new Error('No Base64 Decode');
    }

}

String.prototype.Aesencrypt = function(key, bits = 256) {
    return AesCtr.encrypt(this, key, bits)
};

String.prototype.Aesdecrypt = function(key, bits = 256) {
    return AesCtr.Aesdecrypt(this, key, bits)
};

// AffineCipher
String.prototype.Afencrypt = function(a, b) {
	const alphabet = 'abcdefghijklmnopqrstuvwxyz'.split('')
	let array = [];
	for (let i of this) {
		array.push(alphabet.indexOf(i.toLowerCase()))
	}
	let output = "";
	let cle = [];
	let divtem = "";
	for (let i of array) {
		const image = alphabet[(i * a + b) % 26]
		output += image
		const div = Math.floor((i * a + b) / 26).toString()
		cle.push(div)
	}
	return [output, cle.join("-")]
}
String.prototype.Afdecrypt = function(key, a, b) {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz'.split('');
    const keyArray = key.split("-")
    let array = []
    for (let i of this) {
        array.push(alphabet.indexOf(i))
    }
    let output = "";
    for (var i = 0; i < array.length; i++) {
        const image = alphabet[(keyArray[i] * 26 + array[i] - b) / a]
        output += image
    }
}

// ATBASHCipher

String.prototype.Atencrypt = function() {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz '.split('')
    let output = "";
    for (let i of this) {
        output += alphabet[26 - alphabet.indexOf(i.toLowerCase())]
    }
    return output;
}
String.prototype.Atdecrypt = function() {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz '.split('')
    let output = ""
    for (let i of this) {
        output += alphabet[26 - alphabet.indexOf(i.toLowerCase())]
    }
    return output;
}

// BitShiftCipher

String.prototype.encode = function() {
    let array = [];
    for (let i of this) {
        array.push(i.charCodeAt(0))
    }
    return array
}
String.prototype.Biencrypt = function(key) {
    const encoded = this.encode();
    const keyEncoded = key.encode();
    // console.log(keyEncoded)
    let array = encoded.map(x => {
        x = parseInt(x)
        for (let i of keyEncoded) {
            x = x + 1 << i % 12
        }
        keyEncoded.reverse()
        return x;
    })
    return btoa(unescape(encodeURIComponent(JSON.stringify(array))))
}
String.prototype.Bidecrypt = function(key) {
    const keyEncoded = key.encode()
    let array = JSON.parse(
        decodeURIComponent(escape(window.atob(this)))
    )
    let decrypted = array.map(x => {
        keyEncoded.reverse()
        x = parseInt(x)
        for (let i of keyEncoded) {
            x = x - 1 >> i % 12
        }
        return x;
    })
    return String.fromCharCode(...decrypted)
}


// CaesarCipher
String.prototype.Caencrypt = function(n) {
    let out = "";
    for (let i of this) {
        out += String.fromCharCode(i.charCodeAt(0) + n)
    }
    return out;
}
String.prototype.Cadecrypt = function(n) {
    let out = "";
    for (let i of this) {
        out += String.fromCharCode(i.charCodeAt(0) - n)
    }
    return out;
}

// RailfenceCipher

String.prototype.Raencrypt = function(rows = 3) {
    const arr = this.split(" ").join("").split(""); // remove space + make an array with each letters
    let result = [];
    for (let i = 0; i < rows; i++) {
        result[i] = [];
        for (let j = 0; j < arr.length; j++) {
            const k = j * 2 * (rows - 1) + i;
            k < arr.length ? result[i].push(k) : 1;
            if (i !== 0 && i !== rows) {
                const k2 = j * 2 * (rows - 1) - i;
                k2 < arr.length && k2 > 0 ? result[i].push(k2) : 1;
            }
        }
    }

    function uniqueSort(arr) {
        arr = Array.from(new Set(arr));
        return arr.sort((a, b) => a - b);
    }

    result = result.map(arr => uniqueSort(arr)).reduce((a, b) => a.concat(b)).map(i => arr[i]).join("");
    return result;
}
String.prototype.Radecrypt = function(rows = 3) {
    const div = 2 * (rows - 2) + 2;
    const stringArr = this.split("");
    const len = parseInt(stringArr.length / div);
    let remainder = stringArr.length % div;
    let splitArr = [];
    let tempArr = [];
    const result = [];
    for (let i = 0; i < rows; i++) {
        splitArr.push(i == 0 || i == rows - 1 ? len : 2 * len);
    }
    if (remainder > rows) {
        splitArr = splitArr.map(num => num + 1);
        remainder = remainder - rows;
        for (var j = rows - 2; j >= rows - remainder - 1; j--) {
            splitArr[j]++;
        }
    } else {
        for (var j = 0; j < remainder; j++) {
            splitArr[j]++;
        }
    }

    tempArr = splitArr.map(len => {
        const ans = stringArr.splice(0, len);
        return ans;
    });
    let float = 0;
    let k = 0;

    const lineUp = isAdd => {
        if (k == this.length) {
            return;
        }
        result.push(tempArr[float].shift());
        k++;
        isAdd ? float++ : float--;
        if (float == rows) {
            float = float - 2;
            isAdd = false;
        }
        if (float == 0) {
            isAdd = true;
        }
        lineUp(isAdd);
    }

    lineUp(true);
    return result.join("");
}
// ROT13Cipher
String.prototype.rot13 = function() {
    return this.replace(/([a-m])|([n-z])/ig, (a, b, c) => String.fromCharCode(b ? b.charCodeAt(0) + 13 : c ? c.charCodeAt(0) - 13 : 0) || a);
}
// VigenereCipher
String.prototype.Viencrypt = function(key) {
    function ordA(a) {
        return a.charCodeAt(0) - 65;
    }
    let i = 0;
    let b;
    key = key.toUpperCase().replace(/[^A-Z]/g, '');
    return this.toUpperCase().replace(/[^A-Z]/g, '').replace(/[A-Z]/g, a => {
        b = key[i++ % key.length];
        return String.fromCharCode(((ordA(a) + ordA(b)) % 26 + 65));
    });
}
String.prototype.Videcrypt = function(key) {
    function ordA(a) {
        return a.charCodeAt(0) - 65;
    }
    let i = 0;
    let b;
    key = key.toUpperCase().replace(/[^A-Z]/g, '');
    return this.toUpperCase().replace(/[^A-Z]/g, '').replace(/[A-Z]/g, a => {
        b = key[i++ % key.length];
        return String.fromCharCode(((ordA(a) + 26 - ordA(b)) % 26 + 65));
    });
}
// XORCipher
String.prototype.XOencrypt = function(key) {

    function xorStrings(key, input) {
        let output = '';
        for (let i = 0; i < input.length; i++) {
            const c = input.charCodeAt(i);
            const k = key.charCodeAt(i % key.length);
            output += String.fromCharCode(c ^ k);
        }
        return output;
    }
    return btoa(unescape(encodeURIComponent(xorStrings(key, this))));
}
String.prototype.XOdecrypt = function(key) {

    function xorStrings(key, input) {
        let output = '';
        for (let i = 0; i < input.length; i++) {
            const c = input.charCodeAt(i);
            const k = key.charCodeAt(i % key.length);
            output += String.fromCharCode(c ^ k);
        }
        return output;
    }

    const data = decodeURIComponent(escape(window.atob(this)))
    return xorStrings(key, data);
};




// Hash Functions

// MD5
String.prototype.md5 = function() {
    let string = this;
    function RotateLeft(lValue, iShiftBits) {
        return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
    }

    function AddUnsigned(lX, lY) {
        let lX4;
        let lY4;
        let lX8;
        let lY8;
        let lResult;
        lX8 = (lX & 0x80000000);
        lY8 = (lY & 0x80000000);
        lX4 = (lX & 0x40000000);
        lY4 = (lY & 0x40000000);
        lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
        if (lX4 & lY4) {
            return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
        }
        if (lX4 | lY4) {
            if (lResult & 0x40000000) {
                return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
            } else {
                return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
            }
        } else {
            return (lResult ^ lX8 ^ lY8);
        }
    }

    function F(x, y, z) {
        return (x & y) | ((~x) & z);
    }

    function G(x, y, z) {
        return (x & z) | (y & (~z));
    }

    function H(x, y, z) {
        return (x ^ y ^ z);
    }

    function I(x, y, z) {
        return (y ^ (x | (~z)));
    }

    function FF(a, b, c, d, x, s, ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(F(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    }

    function GG(a, b, c, d, x, s, ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(G(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    }

    function HH(a, b, c, d, x, s, ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(H(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    }

    function II(a, b, c, d, x, s, ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(I(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    }

    function ConvertToWordArray(string) {
        let lWordCount;
        const lMessageLength = string.length;
        const lNumberOfWords_temp1 = lMessageLength + 8;
        const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
        const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
        const lWordArray = Array(lNumberOfWords - 1);
        let lBytePosition = 0;
        let lByteCount = 0;
        while (lByteCount < lMessageLength) {
            lWordCount = (lByteCount - (lByteCount % 4)) / 4;
            lBytePosition = (lByteCount % 4) * 8;
            lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition));
            lByteCount++;
        }
        lWordCount = (lByteCount - (lByteCount % 4)) / 4;
        lBytePosition = (lByteCount % 4) * 8;
        lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
        lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
        lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
        return lWordArray;
    }

    function WordToHex(lValue) {
        let WordToHexValue = "";
        let WordToHexValue_temp = "";
        let lByte;
        let lCount;
        for (lCount = 0; lCount <= 3; lCount++) {
            lByte = (lValue >>> (lCount * 8)) & 255;
            WordToHexValue_temp = `0${lByte.toString(16)}`;
            WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
        }
        return WordToHexValue;
    }

    function Utf8Encode(string) {
        string = string.replace(/\r\n/g, "\n");
        let utftext = "";

        for (let n = 0; n < string.length; n++) {

            const c = string.charCodeAt(n);

            if (c < 128) {
                utftext += String.fromCharCode(c);
            } else if ((c > 127) && (c < 2048)) {
                utftext += String.fromCharCode((c >> 6) | 192);
                utftext += String.fromCharCode((c & 63) | 128);
            } else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                utftext += String.fromCharCode((c & 63) | 128);
            }

        }

        return utftext;
    }

    let x = Array();
    let k;
    let AA;
    let BB;
    let CC;
    let DD;
    let a;
    let b;
    let c;
    let d;
    const S11 = 7;
    const S12 = 12;
    const S13 = 17;
    const S14 = 22;
    const S21 = 5;
    const S22 = 9;
    const S23 = 14;
    const S24 = 20;
    const S31 = 4;
    const S32 = 11;
    const S33 = 16;
    const S34 = 23;
    const S41 = 6;
    const S42 = 10;
    const S43 = 15;
    const S44 = 21;

    string = Utf8Encode(string);

    x = ConvertToWordArray(string);

    a = 0x67452301;
    b = 0xEFCDAB89;
    c = 0x98BADCFE;
    d = 0x10325476;

    for (k = 0; k < x.length; k += 16) {
        AA = a;
        BB = b;
        CC = c;
        DD = d;
        a = FF(a, b, c, d, x[k + 0], S11, 0xD76AA478);
        d = FF(d, a, b, c, x[k + 1], S12, 0xE8C7B756);
        c = FF(c, d, a, b, x[k + 2], S13, 0x242070DB);
        b = FF(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE);
        a = FF(a, b, c, d, x[k + 4], S11, 0xF57C0FAF);
        d = FF(d, a, b, c, x[k + 5], S12, 0x4787C62A);
        c = FF(c, d, a, b, x[k + 6], S13, 0xA8304613);
        b = FF(b, c, d, a, x[k + 7], S14, 0xFD469501);
        a = FF(a, b, c, d, x[k + 8], S11, 0x698098D8);
        d = FF(d, a, b, c, x[k + 9], S12, 0x8B44F7AF);
        c = FF(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1);
        b = FF(b, c, d, a, x[k + 11], S14, 0x895CD7BE);
        a = FF(a, b, c, d, x[k + 12], S11, 0x6B901122);
        d = FF(d, a, b, c, x[k + 13], S12, 0xFD987193);
        c = FF(c, d, a, b, x[k + 14], S13, 0xA679438E);
        b = FF(b, c, d, a, x[k + 15], S14, 0x49B40821);
        a = GG(a, b, c, d, x[k + 1], S21, 0xF61E2562);
        d = GG(d, a, b, c, x[k + 6], S22, 0xC040B340);
        c = GG(c, d, a, b, x[k + 11], S23, 0x265E5A51);
        b = GG(b, c, d, a, x[k + 0], S24, 0xE9B6C7AA);
        a = GG(a, b, c, d, x[k + 5], S21, 0xD62F105D);
        d = GG(d, a, b, c, x[k + 10], S22, 0x2441453);
        c = GG(c, d, a, b, x[k + 15], S23, 0xD8A1E681);
        b = GG(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8);
        a = GG(a, b, c, d, x[k + 9], S21, 0x21E1CDE6);
        d = GG(d, a, b, c, x[k + 14], S22, 0xC33707D6);
        c = GG(c, d, a, b, x[k + 3], S23, 0xF4D50D87);
        b = GG(b, c, d, a, x[k + 8], S24, 0x455A14ED);
        a = GG(a, b, c, d, x[k + 13], S21, 0xA9E3E905);
        d = GG(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8);
        c = GG(c, d, a, b, x[k + 7], S23, 0x676F02D9);
        b = GG(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A);
        a = HH(a, b, c, d, x[k + 5], S31, 0xFFFA3942);
        d = HH(d, a, b, c, x[k + 8], S32, 0x8771F681);
        c = HH(c, d, a, b, x[k + 11], S33, 0x6D9D6122);
        b = HH(b, c, d, a, x[k + 14], S34, 0xFDE5380C);
        a = HH(a, b, c, d, x[k + 1], S31, 0xA4BEEA44);
        d = HH(d, a, b, c, x[k + 4], S32, 0x4BDECFA9);
        c = HH(c, d, a, b, x[k + 7], S33, 0xF6BB4B60);
        b = HH(b, c, d, a, x[k + 10], S34, 0xBEBFBC70);
        a = HH(a, b, c, d, x[k + 13], S31, 0x289B7EC6);
        d = HH(d, a, b, c, x[k + 0], S32, 0xEAA127FA);
        c = HH(c, d, a, b, x[k + 3], S33, 0xD4EF3085);
        b = HH(b, c, d, a, x[k + 6], S34, 0x4881D05);
        a = HH(a, b, c, d, x[k + 9], S31, 0xD9D4D039);
        d = HH(d, a, b, c, x[k + 12], S32, 0xE6DB99E5);
        c = HH(c, d, a, b, x[k + 15], S33, 0x1FA27CF8);
        b = HH(b, c, d, a, x[k + 2], S34, 0xC4AC5665);
        a = II(a, b, c, d, x[k + 0], S41, 0xF4292244);
        d = II(d, a, b, c, x[k + 7], S42, 0x432AFF97);
        c = II(c, d, a, b, x[k + 14], S43, 0xAB9423A7);
        b = II(b, c, d, a, x[k + 5], S44, 0xFC93A039);
        a = II(a, b, c, d, x[k + 12], S41, 0x655B59C3);
        d = II(d, a, b, c, x[k + 3], S42, 0x8F0CCC92);
        c = II(c, d, a, b, x[k + 10], S43, 0xFFEFF47D);
        b = II(b, c, d, a, x[k + 1], S44, 0x85845DD1);
        a = II(a, b, c, d, x[k + 8], S41, 0x6FA87E4F);
        d = II(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0);
        c = II(c, d, a, b, x[k + 6], S43, 0xA3014314);
        b = II(b, c, d, a, x[k + 13], S44, 0x4E0811A1);
        a = II(a, b, c, d, x[k + 4], S41, 0xF7537E82);
        d = II(d, a, b, c, x[k + 11], S42, 0xBD3AF235);
        c = II(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB);
        b = II(b, c, d, a, x[k + 9], S44, 0xEB86D391);
        a = AddUnsigned(a, AA);
        b = AddUnsigned(b, BB);
        c = AddUnsigned(c, CC);
        d = AddUnsigned(d, DD);
    }

    const temp = WordToHex(a) + WordToHex(b) + WordToHex(c) + WordToHex(d);

    return temp.toLowerCase();
};
// SHA256
String.prototype.sha256 = function() {
	let s = this;

    const chrsz = 8;
    const hexcase = 0;

    function safe_add(x, y) {
        const lsw = (x & 0xFFFF) + (y & 0xFFFF);
        const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }

    function S(X, n) {
        return (X >>> n) | (X << (32 - n));
    }

    function R(X, n) {
        return (X >>> n);
    }

    function Ch(x, y, z) {
        return ((x & y) ^ ((~x) & z));
    }

    function Maj(x, y, z) {
        return ((x & y) ^ (x & z) ^ (y & z));
    }

    function Sigma0256(x) {
        return (S(x, 2) ^ S(x, 13) ^ S(x, 22));
    }

    function Sigma1256(x) {
        return (S(x, 6) ^ S(x, 11) ^ S(x, 25));
    }

    function Gamma0256(x) {
        return (S(x, 7) ^ S(x, 18) ^ R(x, 3));
    }

    function Gamma1256(x) {
        return (S(x, 17) ^ S(x, 19) ^ R(x, 10));
    }

    function core_sha256(m, l) {
        const K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);
        const HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
        const W = new Array(64);
        let a;
        let b;
        let c;
        let d;
        let e;
        let f;
        let g;
        let h;
        var i;
        var j;
        let T1;
        let T2;
        m[l >> 5] |= 0x80 << (24 - l % 32);
        m[((l + 64 >> 9) << 4) + 15] = l;
        for (var i = 0; i < m.length; i += 16) {
            a = HASH[0];

            b = HASH[1];

            c = HASH[2];

            d = HASH[3];

            e = HASH[4];

            f = HASH[5];

            g = HASH[6];

            h = HASH[7];
            for (var j = 0; j < 64; j++) {
                if (j < 16) W[j] = m[j + i];
                else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);

                T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
                T2 = safe_add(Sigma0256(a), Maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = safe_add(d, T1);
                d = c;
                c = b;
                b = a;
                a = safe_add(T1, T2);
            }
            HASH[0] = safe_add(a, HASH[0]);

            HASH[1] = safe_add(b, HASH[1]);

            HASH[2] = safe_add(c, HASH[2]);

            HASH[3] = safe_add(d, HASH[3]);

            HASH[4] = safe_add(e, HASH[4]);

            HASH[5] = safe_add(f, HASH[5]);

            HASH[6] = safe_add(g, HASH[6]);

            HASH[7] = safe_add(h, HASH[7]);

        }
        return HASH;
    }

    function str2binb(str) {
        const bin = Array();

        const mask = (1 << chrsz) - 1;

        for (let i = 0; i < str.length * chrsz; i += chrsz) {

            bin[i >> 5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i % 32);

        }

        return bin;

    }


    function Utf8Encode(string) {

        string = string.replace(/\r\n/g, "\n");

        let utftext = "";
        for (let n = 0; n < string.length; n++) {
            const c = string.charCodeAt(n);
            if (c < 128) {

                utftext += String.fromCharCode(c);

            } else if ((c > 127) && (c < 2048)) {

                utftext += String.fromCharCode((c >> 6) | 192);

                utftext += String.fromCharCode((c & 63) | 128);

            } else {

                utftext += String.fromCharCode((c >> 12) | 224);

                utftext += String.fromCharCode(((c >> 6) & 63) | 128);

                utftext += String.fromCharCode((c & 63) | 128);

            }
        }
        return utftext;

    }

    function binb2hex(binarray) {

        const hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";

        let str = "";

        for (let i = 0; i < binarray.length * 4; i++) {

            str += hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8 + 4)) & 0xF) +

                hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8)) & 0xF);

        }

        return str;

    }
    s = Utf8Encode(s);

    return binb2hex(core_sha256(str2binb(s), s.length * chrsz));
}
