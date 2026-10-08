import { abytes, anumber, concatBytes, equalBytes, type TArg, type TRet } from "@noble/ciphers/utils.js";
import type { CipherFunc } from "../types.js";
import { deriveCounter, galoisCtr, GCM_BLOCKSIZE, gcmAuth, gcmBlockAddOne } from "./gcm.utils.js";

/**
 * Wrapper for Galois/Counter (GCM) mode
 * @param encrypter Cipher function for **encryption**, that takes block as input
 * @param blockSize Cipher block size
 * @param plaintext Plaintext
 * @param nonce Nonce
 * @param aad Data to be authenticated
 */
export const gcm_encrypt = (
    encrypter: CipherFunc,
    blockSize: number,
    plaintext: TArg<Uint8Array>,
    nonce: TArg<Uint8Array>,
    aad: TArg<Uint8Array>
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytes(plaintext, undefined, "plaintext");
    abytes(nonce, undefined, "nonce");
    abytes(aad, undefined, "aad");
    if(blockSize != GCM_BLOCKSIZE) throw new Error("Invalid block size. Must be 16");
    if(nonce.length > 16) throw new Error("Invalid nonce");

    const h = encrypter(new Uint8Array(GCM_BLOCKSIZE));
    const counter = new Uint8Array(GCM_BLOCKSIZE);
    deriveCounter(h, counter, nonce);

    const tag_mask = galoisCtr(encrypter, new Uint8Array(GCM_BLOCKSIZE), counter);
    gcmBlockAddOne(counter);

    const out = galoisCtr(encrypter, plaintext, counter);
    const tag = gcmAuth(h, tag_mask, out, aad);
    
    return concatBytes(out, tag);
}

/**
 * Wrapper for Galois/Counter (GCM) mode
 * @param encrypter Cipher function for **encryption**, that takes block as input
 * @param blockSize Cipher block size
 * @param ciphertext Ciphertext
 * @param nonce Nonce
 * @param aad Data to be authenticated
 */
export const gcm_decrypt = (
    encrypter: CipherFunc,
    blockSize: number,
    ciphertext: TArg<Uint8Array>,
    nonce: TArg<Uint8Array>,
    aad: TArg<Uint8Array>
): TRet<Uint8Array> => {
    anumber(blockSize, "blockSize");
    abytes(ciphertext, undefined, "data");
    abytes(nonce, undefined, "nonce");
    abytes(aad, undefined, "aad");
    if(blockSize != GCM_BLOCKSIZE) throw new Error("Invalid block size. Must be 16");
    if(nonce.length > 16) throw new Error("Invalid nonce");
    if(ciphertext.length < 16 || ciphertext.length > ((0x100000000 - 2) * 16 + 16))
        throw new Error("Invalid ciphertext length");

    const h = encrypter(new Uint8Array(GCM_BLOCKSIZE));
    const counter = new Uint8Array(GCM_BLOCKSIZE);
    deriveCounter(h, counter, nonce);

    const tag_mask = galoisCtr(encrypter, new Uint8Array(GCM_BLOCKSIZE), counter);
    gcmBlockAddOne(counter);

    const tag_ct = ciphertext.subarray(-16);
    const ct = ciphertext.subarray(0,-16);
    const tag_expected = gcmAuth(h, tag_mask, ct, aad);
    if(!equalBytes(tag_ct, tag_expected))
        throw new Error("Invalid tag");
    
    return galoisCtr(encrypter, ct, counter);
}