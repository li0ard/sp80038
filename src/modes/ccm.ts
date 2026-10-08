import { type TArg, type TRet, abytes, anumber, concatBytes, equalBytes, numberToBytesBE } from "@noble/ciphers/utils.js";
import { xorBytes } from "../utils.js";
import { cbcmac } from "./cbc.js";
import { ctr } from "./ctr.js";
import type { CipherFunc } from "../types.js";

const aadHeader = (len: number): Uint8Array => {
    if (len < (1 << 16) - (1 << 8))
        return numberToBytesBE(len, 2);
    if (BigInt(len) < (1n << 32n))
        return concatBytes(new Uint8Array([0xFF, 0xFE]), numberToBytesBE(len, 4));
    return concatBytes(new Uint8Array([0xFF, 0xFF]), numberToBytesBE(len, 8));
}
 
const zeroPad = (len: number, blockSize: number): Uint8Array =>
    new Uint8Array((blockSize - (len % blockSize)) % blockSize);

const ctrBlock = (blockSize: number, nonce: Uint8Array, q: number, counter: number): Uint8Array => {
    const blk = new Uint8Array(blockSize);
    blk[0] = q - 1;
    blk.set(nonce, 1);
    blk.set(numberToBytesBE(counter, q), blockSize - q);
    return blk;
}

const ccmTag = (
    encrypter: CipherFunc,
    blockSize: number,
    nonce: Uint8Array,
    aad: Uint8Array,
    msg: Uint8Array,
    t: number,
    q: number
): Uint8Array => {
    const b0 = new Uint8Array(blockSize);
    b0[0] = ((aad.length > 0 ? 1 : 0) << 6) | (((t - 2) / 2) << 3) | (q - 1);
    b0.set(nonce, 1);
    b0.set(numberToBytesBE(msg.length, q), 1 + nonce.length);

    const parts: Uint8Array[] = [b0];
    if (aad.length > 0) {
        const aadBlock = concatBytes(aadHeader(aad.length), aad);
        parts.push(aadBlock, zeroPad(aadBlock.length, blockSize));
    }
    parts.push(msg, zeroPad(msg.length, blockSize));

    const mac = cbcmac(encrypter, blockSize, concatBytes(...parts));
    const s0 = ctr(encrypter, blockSize, new Uint8Array(blockSize), ctrBlock(blockSize, nonce, q, 0));
    return xorBytes(mac.subarray(0, t), s0.subarray(0, t));
}

/**
 * Wrapper for Counter with CBC-MAC (CCM) mode
 * @param encrypter Cipher function for **encryption**, that takes block as input
 * @param blockSize Cipher block size
 * @param plaintext Plaintext
 * @param nonce Nonce
 * @param aad Data to be authenticated
 * @param t Tag size (in bytes)
 */
export const ccm_encrypt = (
    encrypter: CipherFunc,
    blockSize: number,
    plaintext: TArg<Uint8Array>,
    nonce: TArg<Uint8Array>,
    aad: TArg<Uint8Array>,
    t: number = blockSize
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytes(plaintext, undefined, "plaintext");
    abytes(nonce, undefined, "nonce");
    abytes(aad, undefined, "aad");
    anumber(t, "t");

    const q = 15 - nonce.length;
    if (nonce.length < 7 || nonce.length > 13)
        throw new Error("Invalid nonce length (7-13 bytes)");
    if (t < 4 || t > 16 || (t & 1))
        throw new Error("Invalid tag length (even, 4-16)");
    if (BigInt(plaintext.length) >= (1n << BigInt(q * 8)))
        throw new Error("Message too long for given nonce size");

    const tag = ccmTag(encrypter, blockSize, nonce, aad, plaintext, t, q);
    const ciphertext = ctr(encrypter, blockSize, plaintext, ctrBlock(blockSize, nonce, q, 1));

    return concatBytes(ciphertext, tag);
}

/**
 * Wrapper for Counter with CBC-MAC (CCM) mode
 * @param encrypter Cipher function for **encryption**, that takes block as input
 * @param blockSize Cipher block size
 * @param ciphertext Ciphertext
 * @param nonce Nonce
 * @param aad Data to be authenticated
 * @param t Tag size (in bytes)
 */
export const ccm_decrypt = (
    encrypter: CipherFunc,
    blockSize: number,
    ciphertext: TArg<Uint8Array>,
    nonce: TArg<Uint8Array>,
    aad: TArg<Uint8Array>,
    t: number = blockSize
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytes(ciphertext, undefined, "ciphertext");
    abytes(nonce, undefined, "nonce");
    abytes(aad, undefined, "aad");
    anumber(t, "t");
    if (ciphertext.length < t) throw new Error("Input too short (no tag)");

    const ct = ciphertext.subarray(0, ciphertext.length - t);
    const receivedTag = ciphertext.subarray(-t);
    const q = 15 - nonce.length;
    if (nonce.length < 7 || nonce.length > 13)
        throw new Error("Invalid nonce length (7-13 bytes)");
    if (t < 4 || t > 16 || (t & 1))
        throw new Error("Invalid tag length (even, 4-16)");
    if (BigInt(ct.length) >= (1n << BigInt(q * 8)))
        throw new Error("Message too long for given nonce size");

    const plaintext = ctr(encrypter, blockSize, ct, ctrBlock(blockSize, nonce, q, 1));
    const expectedTag = ccmTag(encrypter, blockSize, nonce, aad, plaintext, t, q);
    if (!equalBytes(expectedTag, receivedTag)) throw new Error("Authentication failed: invalid tag");

    return plaintext;
}