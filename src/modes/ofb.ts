import type { TArg, TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { checkBlocksize, checkIvSize, xorBytes } from "../utils.js";


/**
 * Wrapper for Output Feedback (OFB) mode
 * 
 * @param encrypter Cipher function for **encryption**, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 * @param iv Initialization vector
 */
export const ofb = (
    encrypter: CipherFunc,
    blockSize: number,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>
): TRet<Uint8Array> => {
    checkBlocksize(blockSize);
    checkIvSize(iv, blockSize);

    let buf = new Uint8Array(iv);
    const output = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += blockSize) {
        const enc = encrypter(buf);
        output.set(xorBytes(enc, data.subarray(i, i + blockSize)), i);
        buf = enc;
    }

    return output;
}