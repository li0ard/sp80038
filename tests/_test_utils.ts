import { ecb } from "@noble/ciphers/aes.js";
import { hexToBytes, type TArg, type TRet } from "@noble/ciphers/utils.js";

// Bypass key reusing error
export const getEncrypter = (key: TArg<Uint8Array>) =>
    (data: TArg<Uint8Array>): TRet<Uint8Array> => ecb(key, { disablePadding: true }).encrypt(data);

export const getDecrypter = (key: TArg<Uint8Array>) =>
    (data: TArg<Uint8Array>): TRet<Uint8Array> => ecb(key, { disablePadding: true }).decrypt(data);

export const IV = hexToBytes("000102030405060708090a0b0c0d0e0f");
export const IV2 = hexToBytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
export const PLAINTEXT = hexToBytes(
    "6bc1bee22e409f96e93d7e117393172a" + 
    "ae2d8a571e03ac9c9eb76fac45af8e51" + 
    "30c81c46a35ce411e5fbc1191a0a52ef" + 
    "f69f2445df4f9b17ad2b417be66c3710"
);

export const KEY128 = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
export const KEY192 = hexToBytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
export const KEY256 = hexToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");