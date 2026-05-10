import { concatBytes, numberToBytesBE, type TArg, type TRet } from "@noble/ciphers/utils.js";
import { xorBytes } from "../utils.js";
import { GHASH } from "@noble/ciphers/_polyval.js";

export const GCM_BLOCKSIZE = 16;

export const gcmBlockAddOne = (a: TArg<Uint8Array>) => {
    if (a[12] === 0xff && a[13] === 0xff && a[14] === 0xff && a[15] === 0xff)
        throw new Error("Counter overflow");
    for (let i = 0; i < 4; i++) {
        const t = a[15 - i] + 1;
        a[15 - i] = t & 0xff;
        if (t <= 0xff) return;
    }
}

export const galoisCtr = (
    encrypter: (data: TArg<Uint8Array>) => TRet<Uint8Array>,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>
): TRet<Uint8Array> => {
    if(data.length == 0) return new Uint8Array();

    const output = new Uint8Array(data.length);
    let buf = new Uint8Array(iv);
    for (let i = 0; i < data.length; i += GCM_BLOCKSIZE) {
        const yi = xorBytes(encrypter(buf), data.subarray(i, i + GCM_BLOCKSIZE));
        output.set(yi, i);
        gcmBlockAddOne(buf);
    }

    return output;
}

export const deriveCounter = (
    H: TArg<Uint8Array>,
    counter: TArg<Uint8Array>,
    nonce: TArg<Uint8Array>
) => {
    counter.fill(0)
    if(nonce.length == 12) {
        counter.set(nonce);
        counter[15] = 1;
    } else {
        const lenBlock = numberToBytesBE(nonce.length * 8, 16);
        const J = new GHASH(H).update(nonce).update(lenBlock).digest();
        counter.set(J);
    }
}

export const gcmAuth = (
    H: TArg<Uint8Array>,
    tag_mask: TArg<Uint8Array>,
    ciphertext: TArg<Uint8Array>,
    aad: TArg<Uint8Array>
): TRet<Uint8Array> => {
    const S = new GHASH(H)
    .update(aad).update(ciphertext)
    .update(concatBytes(
        numberToBytesBE(aad.length * 8, 8),
        numberToBytesBE(ciphertext.length * 8, 8)
    )).digest();
    
    return xorBytes(tag_mask, S);
}