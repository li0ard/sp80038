import { hexToBytes } from "@noble/ciphers/utils.js";
import { describe, test, expect } from "bun:test";
import { kw_decrypt, kw_encrypt } from "./kw.js";
import { getDecrypter, getEncrypter, IV as IV_ } from "./_test_utils.js";

describe("KW", () => {
    test("128 bits", () => {
        const pt = hexToBytes("00112233445566778899AABBCCDDEEFF");
        const ct = hexToBytes("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
        
        expect(kw_encrypt(getEncrypter(IV_), 16, pt)).toStrictEqual(ct);
        expect(kw_decrypt(getDecrypter(IV_), 16, ct)).toStrictEqual(pt);
    });

    test("128 bits (192 bit KEK)", () => {
        const key = hexToBytes("000102030405060708090A0B0C0D0E0F1011121314151617")
        const pt = hexToBytes("00112233445566778899AABBCCDDEEFF");
        const ct = hexToBytes("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D");
        
        expect(kw_encrypt(getEncrypter(key), 16, pt)).toStrictEqual(ct);
        expect(kw_decrypt(getDecrypter(key), 16, ct)).toStrictEqual(pt);
    });

    test("128 bits (256 bit KEK)", () => {
        const key = hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        const pt = hexToBytes("00112233445566778899AABBCCDDEEFF");
        const ct = hexToBytes("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7");
        
        expect(kw_encrypt(getEncrypter(key), 16, pt)).toStrictEqual(ct);
        expect(kw_decrypt(getDecrypter(key), 16, ct)).toStrictEqual(pt);
    });

    test("192 bits", () => {
        const key = hexToBytes("000102030405060708090A0B0C0D0E0F1011121314151617")
        const pt = hexToBytes("00112233445566778899AABBCCDDEEFF0001020304050607");
        const ct = hexToBytes("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2");
        
        expect(kw_encrypt(getEncrypter(key), 16, pt)).toStrictEqual(ct);
        expect(kw_decrypt(getDecrypter(key), 16, ct)).toStrictEqual(pt);
    });

    test("192 bits (256 bit KEK)", () => {
        const key = hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        const pt = hexToBytes("00112233445566778899AABBCCDDEEFF0001020304050607");
        const ct = hexToBytes("A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1");
        
        expect(kw_encrypt(getEncrypter(key), 16, pt)).toStrictEqual(ct);
        expect(kw_decrypt(getDecrypter(key), 16, ct)).toStrictEqual(pt);
    });

    test("256 bits", () => {
        const key = hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
        const pt = hexToBytes("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
        const ct = hexToBytes("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21");
        
        expect(kw_encrypt(getEncrypter(key), 16, pt)).toStrictEqual(ct);
        expect(kw_decrypt(getDecrypter(key), 16, ct)).toStrictEqual(pt);
    });
});

describe("KWP", () => {
    test("128 bits", () => {
        const key = hexToBytes("000102030405060708090A0B0C0D0E0F");
        const pt = hexToBytes("00112233445566");
        const ct = hexToBytes("1B1D4BC2A90B1FA389412B3D40FECB20");
        
        expect(kw_encrypt(getEncrypter(key), 16, pt, true)).toStrictEqual(ct);
        expect(kw_decrypt(getDecrypter(key), 16, ct, true)).toStrictEqual(pt);
    });

    test("192 bits", () => {
        const key = hexToBytes("000102030405060708090A0B0C0D0E0F1011121314151617");
        const pt = hexToBytes("00112233445566778899AABBCCDDEEFF0001020304");
        const ct = hexToBytes("A402348F1956DB968FDDFD8976420F9DDEB7183CF16B91B0AEB74CAB196C343E");
        
        expect(kw_encrypt(getEncrypter(key), 16, pt, true)).toStrictEqual(ct);
        expect(kw_decrypt(getDecrypter(key), 16, ct, true)).toStrictEqual(pt);
    });

    test("256 bits", () => {
        const key = hexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        const pt = hexToBytes("00112233445566778899AABBCCDDEEFF000102030405060708090A0B");
        const ct = hexToBytes("0942747DB07032A3F04CDB2E7DE1CBA038F92BC355393AE9A0E4AE8C901912AC3D3AF0F16D240607");
        
        expect(kw_encrypt(getEncrypter(key), 16, pt, true)).toStrictEqual(ct);
        expect(kw_decrypt(getDecrypter(key), 16, ct, true)).toStrictEqual(pt);
    });
});