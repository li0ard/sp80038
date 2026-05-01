import type { TArg, TRet } from "@noble/ciphers/utils.js";

/** Cipher function */
export type CipherFunc = (data: TArg<Uint8Array>) => TRet<Uint8Array>;