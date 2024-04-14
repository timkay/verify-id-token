
import * as crypto from 'node:crypto';

import {jwtVerify} from "jose";
import {importX509} from "jose";
const inFlight = new Map();
const cache = new Map();

function decodeJwt(token) {
}

async function getKey(keyId) {
    const certificateURL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
    const res = await fetch(certificateURL);
    if (!res.ok) {
        const error = await res.json().then((data) => data.error.message).catch(() => undefined);
        throw new FetchError(error ?? "Failed to fetch the public key", {response: res});
    }
    const cert = (await res.json())[keyId];
    return crypto.createPublicKey(cert).export({type:'spki', format:'pem'});
}

async function verifyIdToken(idToken, clientId) {
    const base64ToBuffer = item => new Uint8Array(Buffer.from(item, 'base64'));
    const base64ToText = item => new TextDecoder().decode(base64ToBuffer(item));
    const base64JSONToObject = item => JSON.parse(base64ToText(item));
    const textToBase64 = item => new TextEncoder().encode(item);

    let issuer = `https://securetoken.google.com/${clientId}`;
    const now = Math.floor(Date.now() / 1000);

    let [encodedHeader, encodedPayload, encodedSignature] = idToken.split('.');

    if (typeof encodedHeader !== 'string' || !encodedHeader) throw new Error();
    if (typeof encodedPayload !== 'string' || !encodedPayload) throw new Error();
    if (typeof encodedSignature !== 'string' || !encodedSignature) throw new Error();
    const header = base64JSONToObject(encodedHeader);
    const payload = base64JSONToObject(encodedPayload);
    if (!header) throw new Error();
    if (!payload) throw new Error();

    const cert = await getKey(header.kid);
    const spki = cert.match(/-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----/s)[1].replace(/\s/g, '');
    //console.log('spki', spki);
    const algorithm = {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-256"}};
    const key = await crypto.subtle.importKey('spki', base64ToBuffer(spki), algorithm, true, ['verify']);
    //console.log('spki', key, key.algorithm);

    const signature = base64ToBuffer(encodedSignature);
    const data = textToBase64(encodedHeader + '.' + encodedPayload);

    console.log('---crypto.verify---');
    //console.log('algorithm', algorithm);
    //console.log('key', key);
    //console.log('key', crypto.KeyObject.from(key));
    //console.log('signature', signature);
    //console.log('data', data);
    const success = await crypto.verify('sha256', data, key, signature);
    console.log('HERE', {success});
    const success2 = await crypto.subtle.verify(key.algorithm, key, signature, data);
    console.log('HERE', {success2});

    return;
    const {payload: verifiedPayload} = await jwtVerify(idToken, key, {
        audience: clientId,
        issuer,
        maxTokenAge: '1h',
        clockTolerance: '5m'
    });
    if (!payload.sub) throw new Error(`Missing "sub" claim`);

    if (typeof payload.auth_time === 'number' && payload.auth_time > now) {
        throw new Error(`Unexpected "auth_time" claim value`);
    }
    return payload;
}

const idToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImYyOThjZDA3NTlkOGNmN2JjZTZhZWNhODExNmU4ZjYzMDlhNDQwMjAiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiVGltIEtheSIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NLWkk1SHFSRlJWdEl1aG5kRnZlSDNXVnBJY2VqUUlfNWhYc0ZHb0RYN0FKTjg9czk2LWMiLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vcGNiYXJ0LTYyY2IxIiwiYXVkIjoicGNiYXJ0LTYyY2IxIiwiYXV0aF90aW1lIjoxNzEzMTE4NDY3LCJ1c2VyX2lkIjoiY1o3UWY2V05VR2V4NHRQc1pxRXV4eFExMk1mMSIsInN1YiI6ImNaN1FmNldOVUdleDR0UHNacUV1eHhRMTJNZjEiLCJpYXQiOjE3MTMxMTg0NjgsImV4cCI6MTcxMzEyMjA2OCwiZW1haWwiOiJ0aW1rYXlAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsiZ29vZ2xlLmNvbSI6WyIxMDY5Mzg1MDE5MjI5MTM3NDM4OTIiXSwiZW1haWwiOlsidGlta2F5QGdtYWlsLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6Imdvb2dsZS5jb20ifX0.BLnmDnN3MtcrOew4KbREHmsar_Ty2fPp8a8CxgeSw9om5x7GWOH0_h7qhT39rgWOlcLoam3U-rYNsF9x1k_sVv0P-erJ6ZoxfxKkY31MZxLCTkGvIoQmXsfLSwmhOSBt5xY2DHjoonP3lDZpdmiIat56frwGFKCt3nzuKibUjbxpYAUuZ2LNHpT0gO7dLNZ85VKYyyGXYYpiys_TxbQTviXppUX0zj0FJLcdZ92ZRg3lp05vrt4bSr6EWjFv-r7pkQjBdz87Ju-K-lnz2DnAUddJY0OtZExxXtxJvY3zjsw4QKacwj5vsZV750jSBwnMYtwkjn-7f9AyvfVFBNx-EA'

const [headerJSON, payloadJSON, signature] = idToken.split(/\./);
const header = JSON.parse(atob(headerJSON));
const payload = JSON.parse(atob(payloadJSON));

let decoded = await verifyIdToken(idToken, 'pcbart-62cb1');

console.log({decoded});
