import type { TArg, TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { checkBlocksize, checkDataAligned } from "../utils.js";

/**
 * Wrapper for Electronic Codebook (ECB) Mode
 * 
 * @param crypter Cipher function for encryption/decryption, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 */
export const ecb = (
    crypter: CipherFunc,
    blockSize: number,
    data: TArg<Uint8Array>
): TRet<Uint8Array> => {
    checkBlocksize(blockSize);
    checkDataAligned(data, blockSize);

    const output = new Uint8Array(data.length);
    for(let i = 0; i < data.length; i += blockSize)
        output.set(crypter(data.subarray(i, i + blockSize)), i);

    return output;
}