import { xorBytes } from '../utils.js'
import { ctr } from './ctr.js';
import { cmac } from './cmac.js';
import { abytes, anumber, concatBytes, copyBytes, equalBytes, type TArg, type TRet } from '@noble/ciphers/utils.js';
import type { CipherFunc } from '../types.js';

const SIV_BLOCKSIZE = 16;

const dbl = (block: TArg<Uint8Array>): TRet<Uint8Array> => {
    const out = new Uint8Array(block.length);
    let carry = 0;
    for (let i = block.length - 1; i >= 0; i--) {
        const next = block[i] >>> 7;
        out[i] = (block[i] << 1) | carry;
        carry = next;
    }
    out[block.length - 1] ^= 0x87 & -carry;
    return out;
}

const s2v = (
    macEncrypter: CipherFunc,
    blockSize: number,
    strings: TArg<Uint8Array[]>
): TRet<Uint8Array> => {
    const d = cmac(macEncrypter, blockSize, new Uint8Array(blockSize));
    for (let i = 0; i < strings.length - 1; i++)
        d.set(xorBytes(dbl(d), cmac(macEncrypter, blockSize, strings[i])));

    const last = strings[strings.length - 1];
    let t: Uint8Array;
    if (last.length >= blockSize) {
        t = copyBytes(last);
        const offset = t.length - blockSize;
        for (let i = 0; i < blockSize; i++) t[offset + i] ^= d[i];
    } else {
        const padded = new Uint8Array(blockSize);
        padded.set(last);
        padded[last.length] = 0x80;
        t = xorBytes(dbl(d), padded);
    }

    return cmac(macEncrypter, blockSize, t);
}

const ctrIv = (v: TArg<Uint8Array>): TRet<Uint8Array> => {
    const q = copyBytes(v);
    q[8] &= 0x7f;
    q[12] &= 0x7f;
    return q;
}

export const siv_encrypt = (
    macEncrypter: CipherFunc,
    ctrEncrypter: CipherFunc,
    blockSize: number,
    plaintext: TArg<Uint8Array>,
    aad: TArg<Uint8Array[]> = []
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytes(plaintext, undefined, "plaintext");
    aad.forEach(i => abytes(i));
    if (blockSize !== SIV_BLOCKSIZE)
        throw new Error(`Invalid block size. ${blockSize}. Must be 16`);
    if (aad.length > 126)
        throw new Error(`Too many AAD components. Expected <= 126`);

    const v = s2v(macEncrypter, blockSize, [...aad, plaintext]),
        c = ctr(ctrEncrypter, blockSize, plaintext, ctrIv(v));

    return concatBytes(v,c);
}

export const siv_decrypt = (
    macEncrypter: CipherFunc,
    ctrEncrypter: CipherFunc,
    blockSize: number,
    ciphertext: TArg<Uint8Array>,
    aad: TArg<Uint8Array[]> = []
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytes(ciphertext, undefined, "ciphertext");
    aad.forEach(i => abytes(i));
    if (blockSize !== SIV_BLOCKSIZE)
        throw new Error(`Invalid block size. ${blockSize}. Must be 16`);
    if (aad.length > 126)
        throw new Error(`Too many AAD components. Expected <= 126`);
    if (ciphertext.length < blockSize)
        throw new Error(`Invalid data size. Expected at least ${blockSize}`);

    const v = ciphertext.subarray(0, blockSize),
        c = ciphertext.subarray(blockSize);

    const p = ctr(ctrEncrypter, blockSize, c, ctrIv(v)),
        t = s2v(macEncrypter, blockSize, [...aad, p]);
    if (!equalBytes(t, v)) throw new Error('Invalid tag');

    return p;
}