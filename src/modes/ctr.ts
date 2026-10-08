import { abytes, anumber, copyBytes, type TArg, type TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { xorBytes } from "../utils.js";

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
 * @param msg Input message
 * @param iv Initialization vector
 */
export const ctr = (
    encrypter: CipherFunc,
    blockSize: number,
    msg: TArg<Uint8Array>,
    iv: TArg<Uint8Array>
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytes(msg, undefined, "msg");
    abytes(iv, blockSize, "iv");

    const buf = copyBytes(iv);
    const output = new Uint8Array(msg.length);
    for (let i = 0; i < msg.length; i += blockSize) {
        const ct = xorBytes(encrypter(buf), msg.subarray(i, i + blockSize));
        output.set(ct, i);
        incrementCounter(buf);
    }

    return output;
}