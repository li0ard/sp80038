import { abytes, anumber, copyBytes, type TArg, type TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { abytesAligned, xorBytes } from "../utils.js";

/**
 * Wrapper for Cipher Block Chaining (CBC) mode
 * @param encrypter Cipher function for encryption, that takes block as input
 * @param blockSize Cipher block size
 * @param plaintext Plaintext
 * @param iv Initialization vector
 */
export const cbc_encrypt = (
    encrypter: CipherFunc,
    blockSize: number,
    plaintext: TArg<Uint8Array>,
    iv: TArg<Uint8Array>
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytesAligned(plaintext, blockSize, "plaintext");
    abytes(iv, blockSize, "iv");

    const buf = copyBytes(iv),
        output = new Uint8Array(plaintext.length);
    for(let i = 0; i < plaintext.length; i += blockSize) {
        const blk = encrypter(xorBytes(plaintext.subarray(i, i + blockSize), buf));
        output.set(blk, i);
        buf.set(blk);
    }

    return output;
}

/**
 * Wrapper for Cipher Block Chaining (CBC) mode
 * @param decrypter Cipher function for decryption, that takes block as input
 * @param blockSize Cipher block size
 * @param ciphertext Ciphertext
 * @param iv Initialization vector
 */
export const cbc_decrypt = (
    decrypter: CipherFunc,
    blockSize: number,
    ciphertext: TArg<Uint8Array>,
    iv: TArg<Uint8Array>
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytesAligned(ciphertext, blockSize, "ciphertext");
    abytes(iv, blockSize, "iv");

    const buf = copyBytes(iv),
        output = new Uint8Array(ciphertext.length);
    for(let i = 0; i < ciphertext.length; i+= blockSize) {
        const blk = ciphertext.subarray(i,i + blockSize);
        output.set(xorBytes(decrypter(blk), buf), i);
        buf.set(blk);
    }

    return output;
}

/** Wrapper for CBC-MAC */
export const cbcmac = (
    encrypter: CipherFunc,
    blockSize: number,
    msg: TArg<Uint8Array>
): TRet<Uint8Array> => cbc_encrypt(
    encrypter,
    blockSize,
    msg,
    new Uint8Array(blockSize)
).slice(-blockSize);