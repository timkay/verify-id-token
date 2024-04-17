
import {strict as assert} from 'node:assert';
import * as crypto from 'node:crypto';

//const base64ToBuffer = item => new Uint8Array(Buffer.from(item, 'base64url'));
const base64ToBuffer = item => Uint8Array.from(atob(item.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0));
const base64ToText = item => new TextDecoder().decode(base64ToBuffer(item));
const base64JSONToObject = item => JSON.parse(base64ToText(item));
const textToBuffer = item => new TextEncoder().encode(item);
const bufferToText = item => new TextDecoder().decode(item);
const bufferToBase64 = item => btoa(Array.from(item, ch => String.fromCharCode(ch)).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function decodeDer(octets, depth = 0) {

    function getClassFormTagLength() {
        const start = position;
        const octet = octets[position++];
        const cls = octet >> 6;
        const form = (octet & 0x20) >> 5;
        let tag = octet & 0x1f;
        if (tag === 0x1f) {
            tag = 0;
            for (;;) {
                const octet = octets[position++];
                tag = tag << 7 | octet & ~0x80;
                if (octet & 0x80) break;
            }
        }
        let length = octets[position++];
        if (length & 0x80) {
            const n = length & 0x7f;
            length = 0;
            for (let i = 0; i < n; i++) {
                length = (length << 8) | octets[position++];
            }
        }
        //const data = [...octets.subarray(position, position + length)].map(x => x.toString(16).padStart(2, '0')).join('');
        const data = octets.subarray(start, position + length);
        return {class: cls, form, tag, length, data};
    }

    let elems = [];
    let position = 0;

    while (position < octets.length) {
        const result = getClassFormTagLength();
        let value = ''
        if (result.class === 0) { // Universal tags
            if (result.tag === 2) {
                result.type = 'INTEGER';
                value = BigInt(0);
                for (let i = 0; i < result.length; i++) {
                    value = value * 256n + BigInt(octets[position + i]);
                }
                value = value.toString();
            }
            if (result.tag === 1) {
                result.type = 'BOOLEAN';
                value = result.data;
            }
            if (result.tag === 3) {
                result.type = 'BIT STRING';
                result.extra = octets[position++];
                if (result.extra !== 0) {
                    console.log('extra bits');
                }
                //assert(result.extra == 0); // number of unused bits in last octet
                value = [...octets.subarray(position + 1, position + result.length)].map(x => x.toString(16).padStart(2, '0')).join('').substr(0, 40);
            }
            if (result.tag === 4) {
                result.type = 'OCTET STRING';
                value = result.data;
            }
            if (result.tag === 5) {
                result.type = 'NULL';
                value = result.data;
            }
            if (result.tag === 6) {
                result.type = 'OBJECT IDENTIFIER';
                const x = Math.min(Math.floor(octets[position] / 40), 2);
                value = x + '.' + (octets[position] - 40 * x);
                let accum = 0;
                for (let i = 1; i < result.length; i++) {
                    accum = (accum << 7) + (octets[position + i] & 0x7f);
                    if (!(octets[position + i] & 0x80)) {
                        value += '.' + accum.toString();
                        accum = 0;
                        continue;
                    }
                }
                if (accum) value += '.' + accum;
            }
            if (result.tag === 12) {
                result.type = 'UTF8String';
                value = bufferToText(octets.subarray(position, position + result.length));
            }
            if (result.tag === 16) {
                result.type = 'SEQUENCE';
            }
            if (result.tag === 17) {
                result.type = 'SET';
            }
            if (result.tag === 19) {
                result.type = 'PrintableString';
                value = [...octets.subarray(position, position + result.length)].join('');
            }
            if (result.tag === 20) {
                result.type = 'T61String';
                value = [...octets.subarray(position, position + result.length)].join('');
            }
            if (result.tag === 22) {
                result.type = 'IA5STRING';
                value = [...octets.subarray(position, position + result.length)].join('');
            }
            if (result.tag === 23) {
                result.type = 'UTCTime';
                value = bufferToText(octets.subarray(position, position + result.length));
            }
        }
        if (value) delete result.tag;
        const form = result.form;
        delete result.form;
        console.log('  '.repeat(depth), result.class, result.type || result.tag, `(${result.length})`, value);
        if (form === 1) {
            const der = decodeDer(octets.subarray(position, position + result.length), depth + 1);
            // if (Array.isArray(der) && Array.isArray(der[0])) {
            //     console.log('der/der', JSON.stringify(der[0], null, 4));
            // }
            elems.push({type: result.type || result.tag, der, data: result.data});
        } else {
            elems.push({type: result.type || result.tag, value, data: result.data});
        }
        position += result.length;
    }

    return elems;
}

async function verifyIdToken(idToken, clientId) {

    let issuer = `https://securetoken.google.com/${clientId}`;
    const certificateURL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
    const now = Math.floor(Date.now() / 1000);

    let [encodedHeader, encodedPayload, encodedSignature] = idToken.split('.');
    const header = base64JSONToObject(encodedHeader);
    const payload = base64JSONToObject(encodedPayload);

    if (payload.iss != issuer) throw new Error('Token is improperly issued');
    // if (!(payload.iat <= now && now <= payload.exp)) throw new Error('Token is expired');

    const res = await fetch(certificateURL);
    if (!res.ok) {
        const error = await res.json().then((data) => data.error.message).catch(() => undefined);
        throw new FetchError(error ?? "Failed to fetch the public key", {response: res});
    }
    const x509 = (await res.json())[header.kid];

    const der = base64ToBuffer(x509.match(/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s)[1].replace(/\s/g, ''));
    const elems = decodeDer(der);
    const elem = elems?.[0]?.der?.[0]?.der?.[6];
    if (elem?.der?.[0]?.der?.[0]?.value !== '1.2.840.113549.1.1.1') {
        throw new Error('Public key not found in cert');
    }
    const spki = elem.data;

    if (0) {
        const obj = parseCertificate(asn1);
        console.log('contents', bufferToText(obj.contents));
        // console.log('pem', pem);
        // console.log('pem', base64ToText(pem));
        // const key1 = new crypto.X509Certificate(x509).publicKey;
        // console.log('key1', key1);
    }

    // const cert = await crypto.createPublicKey(x509).export({type:'spki', format:'pem'});
    // const spki = cert.match(/-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----/s)[1].replace(/\s/g, '');

    console.log('spki', spki);

    const algorithm = {name: 'RSASSA-PKCS1-v1_5', hash: {name: "SHA-256"}};
    const key = await crypto.subtle.importKey('spki', base64ToBuffer(spki), algorithm, true, ['verify']);
    console.log('key', key);

    const signature = base64ToBuffer(encodedSignature);
    const data = textToBuffer(encodedHeader + '.' + encodedPayload);

    const success = await crypto.subtle.verify(key.algorithm, key, signature, data);
    if (success) return payload;

    // const {payload: verifiedPayload} = await jwtVerify(idToken, key, {
    //     audience: clientId,
    //     issuer,
    //     maxTokenAge: '1h',
    //     clockTolerance: '5m'
    // });

    // return payload;
}

const idToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImYyOThjZDA3NTlkOGNmN2JjZTZhZWNhODExNmU4ZjYzMDlhNDQwMjAiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiVGltIEtheSIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NLWkk1SHFSRlJWdEl1aG5kRnZlSDNXVnBJY2VqUUlfNWhYc0ZHb0RYN0FKTjg9czk2LWMiLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vcGNiYXJ0LTYyY2IxIiwiYXVkIjoicGNiYXJ0LTYyY2IxIiwiYXV0aF90aW1lIjoxNzEzMTE4NDY3LCJ1c2VyX2lkIjoiY1o3UWY2V05VR2V4NHRQc1pxRXV4eFExMk1mMSIsInN1YiI6ImNaN1FmNldOVUdleDR0UHNacUV1eHhRMTJNZjEiLCJpYXQiOjE3MTMxMTg0NjgsImV4cCI6MTcxMzEyMjA2OCwiZW1haWwiOiJ0aW1rYXlAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsiZ29vZ2xlLmNvbSI6WyIxMDY5Mzg1MDE5MjI5MTM3NDM4OTIiXSwiZW1haWwiOlsidGlta2F5QGdtYWlsLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6Imdvb2dsZS5jb20ifX0.BLnmDnN3MtcrOew4KbREHmsar_Ty2fPp8a8CxgeSw9om5x7GWOH0_h7qhT39rgWOlcLoam3U-rYNsF9x1k_sVv0P-erJ6ZoxfxKkY31MZxLCTkGvIoQmXsfLSwmhOSBt5xY2DHjoonP3lDZpdmiIat56frwGFKCt3nzuKibUjbxpYAUuZ2LNHpT0gO7dLNZ85VKYyyGXYYpiys_TxbQTviXppUX0zj0FJLcdZ92ZRg3lp05vrt4bSr6EWjFv-r7pkQjBdz87Ju-K-lnz2DnAUddJY0OtZExxXtxJvY3zjsw4QKacwj5vsZV750jSBwnMYtwkjn-7f9AyvfVFBNx-EA'

try {
    let decoded = await verifyIdToken(idToken, 'pcbart-62cb1');
    console.log({decoded});
} catch (err) {
    console.log(err);
}
