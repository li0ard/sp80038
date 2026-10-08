import { abytes, anumber, copyBytes, type TArg, type TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { xorBytes } from "../utils.js";

/**
 * Wrapper for Cipher Feedback (CFB) mode
 * @param encrypter Cipher function for **encryption**, that takes block as input
 * @param blockSize Cipher block size
 * @param plaintext Plaintext
 * @param iv Initialization vector
 * @param s Segment size (in bytes, e.g CFB-8 -> `1`)
 */
export const cfb_encrypt = (
    encrypter: CipherFunc,
    blockSize: number,
    plaintext: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    s: number = blockSize
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytes(plaintext, undefined, "plaintext");
    abytes(iv, blockSize, "iv");
    anumber(s, "s");
    if (s < 1 || s > blockSize) throw new Error("CFB: s must be between 1 and blockSize");

    const buf = copyBytes(iv);
    const output = new Uint8Array(plaintext.length);
    for (let i = 0; i < plaintext.length; i += s) {
        const keystream = encrypter(buf);
        const seg = Math.min(s, plaintext.length - i);
        const ct = xorBytes(keystream.subarray(0, seg), plaintext.subarray(i, i + seg));
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
 * @param ciphertext Ciphertext
 * @param iv Initialization vector
 * @param s Segment size (in bytes, e.g CFB-8 -> `1`)
 */
export const cfb_decrypt = (
    encrypter: CipherFunc,
    blockSize: number,
    ciphertext: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    s: number = blockSize
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytes(ciphertext, undefined, "ciphertext");
    abytes(iv, blockSize, "iv");
    anumber(s, "s");
    if (s < 1 || s > blockSize) throw new Error("CFB: s must be between 1 and blockSize");

    const buf = copyBytes(iv);
    const output = new Uint8Array(ciphertext.length);
    for (let i = 0; i < ciphertext.length; i += s) {
        const keystream = encrypter(buf);
        const seg = Math.min(s, ciphertext.length - i);
        const ct = ciphertext.subarray(i, i + seg);
        output.set(xorBytes(keystream.subarray(0, seg), ct), i);
        
        buf.copyWithin(0, s);
        buf.set(ct, blockSize - s);
    }

    return output;
}