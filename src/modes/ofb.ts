import { abytes, anumber, copyBytes, type TArg, type TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { xorBytes } from "../utils.js";

/**
 * Wrapper for Output Feedback (OFB) mode
 * 
 * @param encrypter Cipher function for **encryption**, that takes block as input
 * @param blockSize Cipher block size
 * @param msg Input message
 * @param iv Initialization vector
 */
export const ofb = (
    encrypter: CipherFunc,
    blockSize: number,
    msg: TArg<Uint8Array>,
    iv: TArg<Uint8Array>
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytes(msg, undefined, "msg");
    abytes(iv, blockSize, "iv");

    const buf = copyBytes(iv),
        output = new Uint8Array(msg.length);
    for (let i = 0; i < msg.length; i += blockSize) {
        const enc = encrypter(buf);
        output.set(xorBytes(enc, msg.subarray(i, i + blockSize)), i);
        buf.set(enc);
    }

    return output;
}