import { abytes, anumber, bytesToNumberBE, copyBytes, numberToBytesBE, type TArg, type TRet } from "@noble/ciphers/utils.js";

export const xorBytes = (a: TArg<Uint8Array>, b: TArg<Uint8Array>): TRet<Uint8Array> => {
    const mlen = Math.min(a.length, b.length);
    const result = new Uint8Array(mlen);
    for(let i = 0; i < mlen; i++) result[i] = a[i] ^ b[i];

    return result;
}

const atitle = (title: string): string => title ? `"${title}" ` : '';

export const abytesAligned = (
    value: TArg<Uint8Array>,
    blockSize: number,
    title: string = ""
): TRet<Uint8Array> => {
    abytes(value, undefined, title);
    anumber(blockSize, "blockSize");
    if (value.length !== 0 && value.length % blockSize === 0) return value as TRet<Uint8Array>;
    
    const ofLen = ` of length aligned to ${blockSize}`;
    const got = `length=${value.length}`;
    const message = atitle(title) + 'expected Uint8Array' + ofLen + ', got ' + got;
    throw new RangeError(message);
}

export const numberToBytesLE = (n: bigint | number, len: number): TRet<Uint8Array> =>
    numberToBytesBE(n, len).reverse();

export const bytesToNumberLE = (bytes: TArg<Uint8Array>): bigint =>
    bytesToNumberBE(copyBytes(bytes).reverse());