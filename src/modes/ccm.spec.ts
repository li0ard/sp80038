import { hexToBytes, type TRet } from "@noble/ciphers/utils.js";
import { describe, test, expect } from "bun:test";
import { ccm_decrypt, ccm_encrypt } from "./ccm";
import { getEncrypter } from "./_test_utils";

const encrypter = getEncrypter(hexToBytes("404142434445464748494A4B4C4D4E4F"));
const NONCE = hexToBytes("101112131415161718191A1B");
const NONCE2 = NONCE.subarray(0,8) as TRet<Uint8Array>;
const NONCE3 = NONCE.subarray(0,7) as TRet<Uint8Array>;

const PT = hexToBytes("202122232425262728292A2B2C2D2E2F3031323334353637");
const PT2 = PT.subarray(0,16) as TRet<Uint8Array>;
const PT3 = PT.subarray(0,4) as TRet<Uint8Array>;

const AAD = hexToBytes("000102030405060708090A0B0C0D0E0F10111213");
const AAD2 = AAD.subarray(0,16) as TRet<Uint8Array>;
const AAD3 = AAD.subarray(0,8) as TRet<Uint8Array>;

describe("CCM", () => {
    test("#1", () => {
        const ct = hexToBytes("7162015B4DAC255D");
        expect(ccm_encrypt(encrypter, 16, PT3, NONCE3, AAD3, 4)).toStrictEqual(ct);
        expect(ccm_decrypt(encrypter, 16, ct, NONCE3, AAD3, 4)).toStrictEqual(PT3);
    });

    test("#2", () => {
        const ct = hexToBytes("D2A1F0E051EA5F62081A7792073D593D1FC64FBFACCD");
        expect(ccm_encrypt(encrypter, 16, PT2, NONCE2, AAD2, 6)).toStrictEqual(ct);
        expect(ccm_decrypt(encrypter, 16, ct, NONCE2, AAD2, 6)).toStrictEqual(PT2);
    });

    test("#3", () => {
        const ct = hexToBytes("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA5484392FBC1B09951");
        expect(ccm_encrypt(encrypter, 16, PT, NONCE, AAD, 8)).toStrictEqual(ct);
        expect(ccm_decrypt(encrypter, 16, ct, NONCE, AAD, 8)).toStrictEqual(PT);
    });
});