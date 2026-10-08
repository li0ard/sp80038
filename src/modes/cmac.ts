import { abytes, anumber, type TArg, type TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { xorBytes } from "../utils.js";

const Rb64 = 0b11011;
const Rb128 = 0b10000111;

const shift1 = (src: Uint8Array, dst: Uint8Array) => {
    let b = 0;
    for(let i = src.length - 1; i >= 0; i--) {
        const bb = src[i] >> 7;
		dst[i] = src[i]<<1 | b;
		b = bb;
    }

    return b;
}

/**
 * Wrapper for CMAC mode
 * @param encrypter Cipher function for encryption, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 */
export const cmac = (
    encrypter: CipherFunc,
    blockSize: number,
    msg: TArg<Uint8Array>
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytes(msg, undefined, "msg");
    const Rb = blockSize === 16 ? Rb128 : Rb64;

    const L = encrypter(new Uint8Array(blockSize));
    
    const k1 = new Uint8Array(blockSize);
    const msb = shift1(L, k1);
    if (msb) k1[blockSize - 1] ^= Rb;

    const k2 = new Uint8Array(blockSize);
    const msb2 = shift1(k1, k2);
    if (msb2) k2[blockSize - 1] ^= Rb;

    const n = Math.ceil(msg.length / blockSize) || 1;
    const lastBlockComplete = msg.length > 0 && msg.length % blockSize === 0;

    const buf = new Uint8Array(blockSize);
    for (let i = 0; i < n - 1; i++) {
        const m = msg.subarray(i * blockSize, (i + 1) * blockSize);
        buf.set(encrypter(xorBytes(buf, m)));
    }

    let lastBlock: Uint8Array;
    if (lastBlockComplete && msg.length > 0) lastBlock = xorBytes(
        msg.subarray((n - 1) * blockSize, n * blockSize),
        k1
    );
    else {
        const padded = new Uint8Array(blockSize);
        const remaining = msg.length - (n - 1) * blockSize;
        padded.set(msg.subarray((n - 1) * blockSize));
        padded[remaining] = 0x80;
        lastBlock = xorBytes(padded, k2);
    }

    return encrypter(xorBytes(buf, lastBlock));
}