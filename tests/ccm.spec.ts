import { hexToBytes } from "@noble/ciphers/utils.js";
import { describe, test, expect } from "bun:test";
import { ccm_decrypt, ccm_encrypt } from "../src/";
import { getEncrypter } from "./_test_utils";

const encrypter = getEncrypter(hexToBytes("404142434445464748494A4B4C4D4E4F"));

describe("CCM", () => {
    test("#1", () => {
        const nonce = hexToBytes("10111213141516");
        const pt = hexToBytes("20212223");
        const aad = hexToBytes("0001020304050607");
        const ct = hexToBytes("7162015B4DAC255D");

        expect(ccm_encrypt(encrypter, 16, pt, nonce, aad, 4)).toStrictEqual(ct);
        expect(ccm_decrypt(encrypter, 16, ct, nonce, aad, 4)).toStrictEqual(pt);
    });

    test("#2", () => {
        const nonce = hexToBytes("1011121314151617");
        const pt = hexToBytes("202122232425262728292A2B2C2D2E2F");
        const aad = hexToBytes("000102030405060708090A0B0C0D0E0F");
        const ct = hexToBytes("D2A1F0E051EA5F62081A7792073D593D1FC64FBFACCD");

        expect(ccm_encrypt(encrypter, 16, pt, nonce, aad, 6)).toStrictEqual(ct);
        expect(ccm_decrypt(encrypter, 16, ct, nonce, aad, 6)).toStrictEqual(pt);
    });

    test("#3", () => {
        const nonce = hexToBytes("101112131415161718191A1B");
        const pt = hexToBytes("202122232425262728292A2B2C2D2E2F3031323334353637");
        const aad = hexToBytes("000102030405060708090A0B0C0D0E0F10111213");
        const ct = hexToBytes("E3B201A9F5B71A7A9B1CEAECCD97E70B6176AAD9A4428AA5484392FBC1B09951");

        expect(ccm_encrypt(encrypter, 16, pt, nonce, aad, 8)).toStrictEqual(ct);
        expect(ccm_decrypt(encrypter, 16, ct, nonce, aad, 8)).toStrictEqual(pt);
    });
});