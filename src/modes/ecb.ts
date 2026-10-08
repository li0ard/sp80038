import { anumber, type TArg, type TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { abytesAligned } from "../utils.js";

/**
 * Wrapper for Electronic Codebook (ECB) Mode
 * 
 * @param crypter Cipher function for encryption/decryption, that takes block as input
 * @param blockSize Cipher block size
 * @param msg Input message
 */
export const ecb = (
    crypter: CipherFunc,
    blockSize: number,
    msg: TArg<Uint8Array>
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytesAligned(msg, blockSize, "msg");
    const output = new Uint8Array(msg.length);
    for(let i = 0; i < msg.length; i += blockSize)
        output.set(crypter(msg.subarray(i, i + blockSize)), i);

    return output;
}