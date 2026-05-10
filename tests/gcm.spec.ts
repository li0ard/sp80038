import { hexToBytes } from "@noble/ciphers/utils.js";
import { describe, test, expect } from "bun:test";
import { gcm_decrypt, gcm_encrypt } from "../src/index.js";
import { getEncrypter } from "./_test_utils.js";

const key = hexToBytes("FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308");
const encrypter = getEncrypter(key.slice(0, 16));
const encrypter2 = getEncrypter(key.slice(0, 24));
const encrypter3 = getEncrypter(key);
const nonce = hexToBytes("CAFEBABEFACEDBADDECAF888");

describe("GCM-AES128", () => {
    // GCM-AES128
    test("#1", () => {
        const pt = new Uint8Array();
        const aad = new Uint8Array();
        const ct = hexToBytes("3247184B3C4F69A44DBCD22887BBB418");

        expect(gcm_encrypt(encrypter, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter, 16, ct, nonce, aad)).toStrictEqual(pt);
    });

    test("#2", () => {
        const pt = hexToBytes("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255");
        const aad = new Uint8Array();
        const ct = hexToBytes("42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091473F59854D5C2AF327CD64A62CF35ABD2BA6FAB4");

        expect(gcm_encrypt(encrypter, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter, 16, ct, nonce, aad)).toStrictEqual(pt);
    });

    test("#3", () => {
        const pt = new Uint8Array();
        const aad = hexToBytes("3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4");
        const ct = hexToBytes("5F91D77123EF5EB9997913849B8DC1E9");

        expect(gcm_encrypt(encrypter, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter, 16, ct, nonce, aad)).toStrictEqual(pt);
    });

    test("#4", () => {
        const pt = hexToBytes("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255");
        const aad = hexToBytes("3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4");
        const ct = hexToBytes("42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091473F598564C0232904AF398A5B67C10B53A5024D");

        expect(gcm_encrypt(encrypter, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter, 16, ct, nonce, aad)).toStrictEqual(pt);
    });

    test("#5", () => {
        const pt = hexToBytes("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39");
        const aad = hexToBytes("3AD77BB40D7A3660A89ECAF32466EF97F5D3D585");
        const ct = hexToBytes("42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091F07C2528EEA2FCA1211F905E1B6A881B");

        expect(gcm_encrypt(encrypter, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter, 16, ct, nonce, aad)).toStrictEqual(pt);
    });

    test("IV = 16 bytes", () => {
        const pt = new Uint8Array();
        const aad = new Uint8Array(16);
        const ct = hexToBytes("CD2C15737E6BE805EAEEB13868557004");
        const nonce2 = new Uint8Array(16);

        expect(gcm_encrypt(encrypter, 16, pt, nonce2, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter, 16, ct, nonce2, aad)).toStrictEqual(pt);
    });
});

describe("GCM-AES192", () => {
    test("#1", () => {
        const pt = new Uint8Array();
        const aad = new Uint8Array();
        const ct = hexToBytes("C835AA88AEBBC94F5A02E179FDCFC3E4");

        expect(gcm_encrypt(encrypter2, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter2, 16, ct, nonce, aad)).toStrictEqual(pt);
    });


    test("#2", () => {
        const pt = hexToBytes("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255");
        const aad = new Uint8Array();
        const ct = hexToBytes("3980CA0B3C00E841EB06FAC4872A2757859E1CEAA6EFD984628593B40CA1E19C7D773D00C144C525AC619D18C84A3F4718E2448B2FE324D9CCDA2710ACADE2569924A7C8587336BFB118024DB8674A14");

        expect(gcm_encrypt(encrypter2, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter2, 16, ct, nonce, aad)).toStrictEqual(pt);
    });

    test("#3", () => {
        const pt = new Uint8Array();
        const aad = hexToBytes("3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4");
        const ct = hexToBytes("02CC773BC919F4E1C5E9C54313BFACE0");

        expect(gcm_encrypt(encrypter2, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter2, 16, ct, nonce, aad)).toStrictEqual(pt);
    });

    test("#4", () => {
        const pt = hexToBytes("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255");
        const aad = hexToBytes("3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4");
        const ct = hexToBytes("3980CA0B3C00E841EB06FAC4872A2757859E1CEAA6EFD984628593B40CA1E19C7D773D00C144C525AC619D18C84A3F4718E2448B2FE324D9CCDA2710ACADE2563B9153B4E7318A5F3BBEAC108F8A8EDB");

        expect(gcm_encrypt(encrypter2, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter2, 16, ct, nonce, aad)).toStrictEqual(pt);
    });

    test("#5", () => {
        const pt = hexToBytes("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39");
        const aad = hexToBytes("3AD77BB40D7A3660A89ECAF32466EF97F5D3D585");
        const ct = hexToBytes("3980CA0B3C00E841EB06FAC4872A2757859E1CEAA6EFD984628593B40CA1E19C7D773D00C144C525AC619D18C84A3F4718E2448B2FE324D9CCDA271093EA28C659E269902A80ACD208E7FC80");

        expect(gcm_encrypt(encrypter2, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter2, 16, ct, nonce, aad)).toStrictEqual(pt);
    });    
});

describe("GCM-AES256", () => {
    test("#1", () => {
        const pt = new Uint8Array();
        const aad = new Uint8Array();
        const ct = hexToBytes("FD2CAA16A5832E76AA132C1453EEDA7E");

        expect(gcm_encrypt(encrypter3, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter3, 16, ct, nonce, aad)).toStrictEqual(pt);
    });

    test("#2", () => {
        const pt = hexToBytes("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255");
        const aad = new Uint8Array();
        const ct = hexToBytes("522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662898015ADB094DAC5D93471BDEC1A502270E3CC6C");

        expect(gcm_encrypt(encrypter3, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter3, 16, ct, nonce, aad)).toStrictEqual(pt);
    });

    test("#3", () => {
        const pt = new Uint8Array();
        const aad = hexToBytes("3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4");
        const ct = hexToBytes("DE34B6DCD4CEE2FDBEC3CEA01AF1EE44");

        expect(gcm_encrypt(encrypter3, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter3, 16, ct, nonce, aad)).toStrictEqual(pt);
    });

    test("#4", () => {
        const pt = hexToBytes("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255");
        const aad = hexToBytes("3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4");
        const ct = hexToBytes("522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662898015ADC06D76F31930FEF37ACAE23ED465AE62");

        expect(gcm_encrypt(encrypter3, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter3, 16, ct, nonce, aad)).toStrictEqual(pt);
    });

    test("#5", () => {
        const pt = hexToBytes("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39");
        const aad = hexToBytes("3AD77BB40D7A3660A89ECAF32466EF97F5D3D585");
        const ct = hexToBytes("522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662E097195F4532DA895FB917A5A55C6AA0");

        expect(gcm_encrypt(encrypter3, 16, pt, nonce, aad)).toStrictEqual(ct);
        expect(gcm_decrypt(encrypter3, 16, ct, nonce, aad)).toStrictEqual(pt);
    });
});