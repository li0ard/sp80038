import type { TArg, TRet } from "@noble/ciphers/utils.js";

export const checkBlocksize = (blockSize: number) => {
    if(blockSize < 1)
        throw new Error(`Invalid block size: ${blockSize}. Block size MUST be positive integer`);
}

export const checkDataAligned = (data: TArg<Uint8Array>, blockSize: number) => { 
    if (data.length % blockSize !== 0)
        throw new Error(`Data not aligned: data length ${data.length} is not a multiple of block size ${blockSize}`);
}

export const checkIvSize = (iv: TArg<Uint8Array>, blockSize: number) => { 
    if (iv.length != blockSize)
        throw new Error(`Invalid IV size: ${iv.length}. IV size MUST equal to block size`);
}

export const xorBytes = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const mlen = Math.min(a.length, b.length);
    const result = new Uint8Array(mlen);
    for(let i = 0; i < mlen; i++) result[i] = a[i] ^ b[i];

    return result;
}