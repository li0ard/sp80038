import { abytes, anumber, bytesToNumberBE, concatBytes, copyBytes, equalBytes, numberToBytesBE, type TArg, type TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { xorBytes } from "../utils.js";

const KW_BLOCKSIZE = 16;
const SEMIBLOCK = 8;

const KW_IV = new Uint8Array(SEMIBLOCK).fill(0xa6);
const KWP_AIV_PREFIX = Uint8Array.of(0xa6, 0x59, 0x59, 0xa6);

const wrapCore = (
    encrypter: CipherFunc,
    iv: TArg<Uint8Array>,
    r: TArg<Uint8Array>
): TRet<Uint8Array> => {
    const n = r.length / SEMIBLOCK,
        out = copyBytes(r);

    const a = copyBytes(iv);
    for(let j = 0; j < 6; j++) {
        for(let i = 0; i < n; i++) {
            const b = encrypter(concatBytes(a, out.subarray(i * SEMIBLOCK, (i + 1) * SEMIBLOCK)));
            a.set(xorBytes(b.subarray(0, SEMIBLOCK), numberToBytesBE(n * j + i + 1, SEMIBLOCK)));
            out.set(b.subarray(SEMIBLOCK, KW_BLOCKSIZE), i * SEMIBLOCK);
        }
    }

    return concatBytes(a, out);
}

const unwrapCore = (
    decrypter: CipherFunc,
    data: TArg<Uint8Array>
): { a: Uint8Array, r: Uint8Array } => {
    const r = data.slice(SEMIBLOCK),
        n = r.length / SEMIBLOCK;

    const a = data.slice(0, SEMIBLOCK);
    for(let j = 5; j >= 0; j--) {
        for(let i = n; i >= 1; i--) {
            const b = decrypter(concatBytes(
                xorBytes(a, numberToBytesBE(n * j + i, SEMIBLOCK)),
                r.subarray((i - 1) * SEMIBLOCK, i * SEMIBLOCK)
            ));
            a.set(b.subarray(0, SEMIBLOCK));
            r.set(b.subarray(SEMIBLOCK, KW_BLOCKSIZE), (i - 1) * SEMIBLOCK);
        }
    }

    return { a, r }
}

/**
 * Wrapper for Key wrap (KW/KWP) mode
 * @param encrypter Cipher function for encryption, that takes block as input
 * @param blockSize Cipher block size
 * @param plaintext Plaintext
 * @param pad Whether to use padding (KWP mode)
 */
export const kw_encrypt = (
    encrypter: CipherFunc,
    blockSize: number,
    plaintext: TArg<Uint8Array>,
    pad: boolean = false
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytes(plaintext, undefined, "plaintext");
    if(blockSize != KW_BLOCKSIZE)
        throw new Error("Invalid block size. Must be 16");

    if(!pad) {
        if(plaintext.length < 16 || plaintext.length % SEMIBLOCK != 0)
            throw new Error("Invalid plaintext length. Must be a multiple of 8 and at least 16");
        return wrapCore(encrypter, KW_IV, plaintext);
    }

    if(plaintext.length < 1 || plaintext.length > 0xffffffff)
        throw new Error("Invalid plaintext length");

    const padded = new Uint8Array(Math.ceil(plaintext.length / SEMIBLOCK) * SEMIBLOCK),
        aiv = concatBytes(KWP_AIV_PREFIX, numberToBytesBE(plaintext.length, 4));
    padded.set(plaintext);

    return padded.length == SEMIBLOCK
        ? encrypter(concatBytes(aiv, padded))
        : wrapCore(encrypter, aiv, padded);
}

/**
 * Wrapper for Key wrap (KW/KWP) mode
 * @param decrypter Cipher function for decryption, that takes block as input
 * @param blockSize Cipher block size
 * @param ciphertext Ciphertext
 * @param pad Whether to use padding (KWP mode)
 */
export const kw_decrypt = (
    decrypter: CipherFunc,
    blockSize: number,
    ciphertext: TArg<Uint8Array>,
    pad: boolean = false
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytes(ciphertext, undefined, "ciphertext");
    if(blockSize != KW_BLOCKSIZE) throw new Error("Invalid block size. Must be 16");
    if(ciphertext.length % SEMIBLOCK != 0 || ciphertext.length < (pad ? 16 : 24))
        throw new Error("Invalid ciphertext length");

    if(!pad) {
        const { a, r } = unwrapCore(decrypter, ciphertext);
        if(!equalBytes(a, KW_IV))
            throw new Error("Invalid integrity check");
        return r as TRet<Uint8Array>;
    }

    let a: Uint8Array, r: Uint8Array;
    if(ciphertext.length == KW_BLOCKSIZE) {
        const b = decrypter(ciphertext);
        a = b.slice(0, SEMIBLOCK);
        r = b.slice(SEMIBLOCK, KW_BLOCKSIZE);
    } else {
        ({ a, r } = unwrapCore(decrypter, ciphertext));
    }

    const mli = Number(bytesToNumberBE(a.subarray(4, SEMIBLOCK))),
        lenOk = mli > r.length - SEMIBLOCK && mli <= r.length;

    let padDiff = 0;
    for(let i = lenOk ? mli : 0; i < r.length; i++)
        padDiff |= r[i];
    if(!(equalBytes(a.subarray(0, 4), KWP_AIV_PREFIX) && lenOk && padDiff == 0)) {
        throw new Error("Invalid integrity check");
    }

    return r.slice(0, mli);
}