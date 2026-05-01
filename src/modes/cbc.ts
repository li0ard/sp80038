import type { TArg, TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { checkBlocksize, checkDataAligned, checkIvSize, xorBytes } from "../utils.js";

/**
 * Wrapper for Cipher Block Chaining (CBC) mode
 * @param encrypter Cipher function for encryption, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 * @param iv Initialization vector
 */
export const cbc_encrypt = (
    encrypter: CipherFunc,
    blockSize: number,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>
): TRet<Uint8Array> => {
    checkBlocksize(blockSize);
    checkDataAligned(data, blockSize)
    checkIvSize(iv, blockSize);

    let buf: TArg<Uint8Array> = new Uint8Array(iv);
    const output = new Uint8Array(data.length);
    for(let i = 0; i < data.length; i += blockSize) {
        const blk = encrypter(xorBytes(data.subarray(i, i + blockSize), buf));
        output.set(blk, i);
        buf = blk.slice();
    }

    return output;
}

/**
 * Wrapper for Cipher Block Chaining (CBC) mode
 * @param decrypter Cipher function for decryption, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 * @param iv Initialization vector
 */
export const cbc_decrypt = (
    decrypter: CipherFunc,
    blockSize: number,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>
): TRet<Uint8Array> => {
    checkBlocksize(blockSize);
    checkDataAligned(data, blockSize)
    checkIvSize(iv, blockSize);

    let buf: TArg<Uint8Array> = new Uint8Array(iv);
    const output = new Uint8Array(data.length);
    for(let i = 0; i < data.length; i+= blockSize) {
        const blk = data.subarray(i,i + blockSize);
        output.set(xorBytes(decrypter(blk), buf), i);
        buf = blk.slice();
    }

    return output;
}