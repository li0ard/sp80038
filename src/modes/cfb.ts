import { type TArg, type TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { checkBlocksize, checkIvSize, xorBytes } from "../utils.js";

/**
 * Wrapper for Cipher Feedback (CFB) mode
 * @param encrypter Cipher function for **encryption**, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 * @param iv Initialization vector
 * @param s Segment size (in bytes, e.g CFB-8 -> `1`)
 */
export const cfb_encrypt = (
    encrypter: CipherFunc,
    blockSize: number,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    s: number = blockSize
): TRet<Uint8Array> => {
    checkBlocksize(blockSize);
    checkIvSize(iv, blockSize);

    if (s < 1 || s > blockSize) throw new Error("CFB: s must be between 1 and blockSize");

    const buf = new Uint8Array(iv);
    const output = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += s) {
        const keystream = encrypter(buf);
        const seg = Math.min(s, data.length - i);
        const ct = xorBytes(keystream.subarray(0, seg), data.subarray(i, i + seg));
        output.set(ct, i);
        
        buf.copyWithin(0, s);
        buf.set(ct, blockSize - s);
    }

    return output;
}

/**
 * Wrapper for Cipher Feedback (CFB) mode
 * @param encrypter Cipher function for **encryption**, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 * @param iv Initialization vector
 * @param s Segment size (in bytes, e.g CFB-8 -> `1`)
 */
export const cfb_decrypt = (
    encrypter: CipherFunc,
    blockSize: number,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    s: number = blockSize
): TRet<Uint8Array> => {
    checkBlocksize(blockSize);
    checkIvSize(iv, blockSize);
    if (s < 1 || s > blockSize) throw new Error("CFB: s must be between 1 and blockSize");

    const buf = new Uint8Array(iv);
    const output = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += s) {
        const keystream = encrypter(buf);
        const seg = Math.min(s, data.length - i);
        const ct = data.subarray(i, i + seg);
        output.set(xorBytes(keystream.subarray(0, seg), ct), i);
        
        buf.copyWithin(0, s);
        buf.set(ct, blockSize - s);
    }

    return output;
}