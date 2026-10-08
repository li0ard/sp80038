import { abytes, anumber, type TArg, type TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { abytesAligned, xorBytes } from "../utils.js";

const crypt = (
    crypter: CipherFunc,
    blockSize: number,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    decrypting: boolean
): TRet<Uint8Array> => {
    const blockSize_x2 = blockSize * 2;
    anumber(blockSize, "blockSize");
    abytesAligned(data, blockSize, "data");
    abytes(iv, blockSize_x2, "iv");

    const out = new Uint8Array(data.length),
        prevOut = iv.slice(decrypting ? blockSize : 0, decrypting ? blockSize_x2 : blockSize),
        prevIn = iv.slice(decrypting ? 0 : blockSize, decrypting ? blockSize : blockSize_x2);
    for (let o = 0; o < data.length; o += blockSize) {
        const block = data.subarray(o, o + blockSize),
            res = xorBytes(crypter(xorBytes(block, prevOut)), prevIn);
        out.set(res, o);
        prevOut.set(res);
        prevIn.set(block);
    }

    return out;
}

export const ige_encrypt = (
    encrypter: CipherFunc,
    blockSize: number,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>
): TRet<Uint8Array> => crypt(encrypter, blockSize, data, iv, false);

export const ige_decrypt = (
    decrypter: CipherFunc,
    blockSize: number,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>
): TRet<Uint8Array> => crypt(decrypter, blockSize, data, iv, true);