import { type TArg, type TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { checkBlocksize, checkIvSize, xorBytes } from "../utils.js";

const incrementCounter = (ctr: Uint8Array) => {
    for(let i = ctr.length - 1; i >= 0; i--) {
        ctr[i]++;
		if (ctr[i] != 0) break;
    }
}

/**
 * Wrapper for Counter (CTR) mode
 * 
 * @param encrypter Cipher function for **encryption**, that takes block as input
 * @param blockSize Cipher block size
 * @param data Input data
 * @param iv Initialization vector
 */
export const ctr = (
    encrypter: CipherFunc,
    blockSize: number,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>
): TRet<Uint8Array> => {
    checkBlocksize(blockSize);
    checkIvSize(iv, blockSize);

    const buf = new Uint8Array(iv);
    const output = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += blockSize) {
        const ct = xorBytes(encrypter(buf), data.subarray(i, i + blockSize));
        output.set(ct, i);
        incrementCounter(buf);
    }

    return output;
}