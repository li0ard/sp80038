import { type TArg, type TRet, abytes, anumber, concatBytes, equalBytes, numberToBytesBE } from "@noble/ciphers/utils.js";
import { xorBytes } from "../utils.js";
import { cbcmac } from "./cbc.js";
import { ctr } from "./ctr.js";
import type { CipherFunc } from "../types.js";

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
    const ivlen = nonce.length;
    const q = 15 - ivlen;
    if (ivlen < 7 || ivlen > 13) throw new Error("Invalid nonce length (7-13 bytes)");
    if (t < 4 || t > 16 || (t & 1)) throw new Error("Invalid tag length (even, 4-16)");

    const maxLen = (1n << BigInt(q * 8));
    if (BigInt(plaintext.length) >= maxLen) throw new Error("Message too long for given nonce size");

    const b0 = new Uint8Array(blockSize);
    b0[0] = ((aad.length > 0 ? 1 : 0) << 6) | (((t - 2) / 2) << 3) | (q - 1);
    b0.set(nonce, 1);
    b0.set(numberToBytesBE(plaintext.length, q), 1 + ivlen);

    let macData = b0;
    if (aad.length > 0) {
        let header: Uint8Array;
        if (aad.length < (1 << 16) - (1 << 8)) header = numberToBytesBE(aad.length, 2);
        else if (BigInt(aad.length) < (1n << 32n))
            header = concatBytes(new Uint8Array([0xFF, 0xFE]), numberToBytesBE(aad.length, 4));
        else
            header = concatBytes(new Uint8Array([0xFF, 0xFF]), numberToBytesBE(aad.length, 8));
        macData = concatBytes(macData, header, aad);
        
        const pad = (blockSize - (macData.length % blockSize)) % blockSize;
        if (pad > 0) macData = concatBytes(macData, new Uint8Array(pad));
    }

    macData = concatBytes(macData, plaintext);
    const pad = (blockSize - (plaintext.length % blockSize)) % blockSize;
    if (pad > 0) macData = concatBytes(macData, new Uint8Array(pad));

    const mac = cbcmac(encrypter, blockSize, macData);

    const makeCtrBlock = (counter: number | bigint): TRet<Uint8Array> => {
        const blk = new Uint8Array(blockSize);
        blk[0] = q - 1;
        blk.set(nonce, 1);
        blk.set(numberToBytesBE(counter, q), blockSize - q);
        return blk;
    }

    const tagKeystream = ctr(encrypter, blockSize, new Uint8Array(blockSize), makeCtrBlock(0));
    const ciphertext = ctr(encrypter, blockSize, plaintext, makeCtrBlock(1));
    const tag = xorBytes(mac.subarray(0, t), tagKeystream.subarray(0, t));

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
    const ivlen = nonce.length;
    const q = 15 - ivlen;
    if (ivlen < 7 || ivlen > 13) throw new Error("Invalid nonce length");
    if (t < 4 || t > 16 || (t & 1)) throw new Error("Invalid tag length");
    if (ciphertext.length < t) throw new Error("Input too short (no tag)");

    const ct = ciphertext.subarray(0, ciphertext.length - t);
    const receivedTag = ciphertext.subarray(-t);

    const maxLen = (1n << BigInt(q * 8));
    if (BigInt(ct.length) >= maxLen) throw new Error("Message too long for given nonce size");

    const makeCtrBlock = (counter: number | bigint): TRet<Uint8Array> => {
        const blk = new Uint8Array(blockSize);
        blk[0] = q - 1;
        blk.set(nonce, 1);
        blk.set(numberToBytesBE(counter, q), blockSize - q);
        return blk;
    };

    const plaintext = ctr(encrypter, blockSize, ct, makeCtrBlock(1));
    const b0 = new Uint8Array(blockSize);
    b0[0] = ((aad.length > 0 ? 1 : 0) << 6) | (((t - 2) / 2) << 3) | (q - 1);
    b0.set(nonce, 1);
    b0.set(numberToBytesBE(ct.length, q), 1 + ivlen);

    let macData = b0;

    if (aad.length > 0) {
        let header: Uint8Array;
        if (aad.length < (1 << 16) - (1 << 8)) header = numberToBytesBE(aad.length, 2);
        else if (BigInt(aad.length) < (1n << 32n))
            header = concatBytes(new Uint8Array([0xFF, 0xFE]), numberToBytesBE(aad.length, 4));
        else
            header = concatBytes(new Uint8Array([0xFF, 0xFF]), numberToBytesBE(aad.length, 8));
        macData = concatBytes(macData, header, aad);
        const pad = (blockSize - (macData.length % blockSize)) % blockSize;
        if (pad > 0) macData = concatBytes(macData, new Uint8Array(pad));
    }

    macData = concatBytes(macData, plaintext);
    const pad = (blockSize - (plaintext.length % blockSize)) % blockSize;
    if (pad > 0) macData = concatBytes(macData, new Uint8Array(pad));

    const mac = cbcmac(encrypter, blockSize, macData);
    const a0 = makeCtrBlock(0);
    const tagKeystream = ctr(encrypter, blockSize, new Uint8Array(blockSize), a0);
    const expectedTag = xorBytes(mac.subarray(0, t), tagKeystream.subarray(0, t));
    if (!equalBytes(expectedTag, receivedTag)) throw new Error("Authentication failed: invalid tag");

    return plaintext;
}