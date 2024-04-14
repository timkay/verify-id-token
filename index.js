
import * as crypto from 'node:crypto';

import {jwtVerify} from "jose";
import {importX509} from "jose";
const inFlight = new Map();
const cache = new Map();

function decodeJwt(token) {
}

/**
 * Imports a public key for the provided Google Cloud (GCP)
 * service account credentials.
 *
 * @throws {FetchError} - If the X.509 certificate could not be fetched.
 */
async function importPublicKey(keyId) {
    return
    const certificateURL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
    const cacheKey = `${certificateURL}?key=${keyId}`;
    const value = cache.get(cacheKey);
    const now = Date.now();
    async function fetchKey() {
        const res = await fetch(certificateURL);
        if (!res.ok) {
            const error = await res
                  .json()
                  .then((data) => data.error.message)
                  .catch(() => undefined);
            throw new FetchError(error ?? "Failed to fetch the public key", {
                response: res,
            });
        }
        const data = await res.json();
        const x509 = data[keyId];
        if (!x509) {
            throw new Error(`Public key "${keyId}" not found.`);
        }
        const key = await importX509(x509, "RS256");
        const maxAge = res.headers.get("cache-control")?.match(/max-age=(\d+)/)?.[1]; // prettier-ignore
        const expires = Date.now() + Number(maxAge ?? "3600") * 1000;
        cache.set(cacheKey, {key, expires});
        inFlight.delete(keyId);
        return key;
    }
    // Attempt to read the key from the local cache
    if (value) {
        if (value.expires > now + 10_000) {
            if (value.expires - now < 600_000) {
                const promise = fetchKey();
                inFlight.set(cacheKey, promise);
            }
            return value.key;
        } else {
            cache.delete(cacheKey);
        }
    }
    // Check if there is an in-flight request for the same key ID
    let promise = inFlight.get(cacheKey);
    // If not, start a new request
    if (!promise) {
        promise = fetchKey();
        inFlight.set(cacheKey, promise);
    }
    return promise;
}

async function getKey(keyId) {
    const certificateURL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
    const res = await fetch(certificateURL);
    if (!res.ok) {
        const error = await res.json().then((data) => data.error.message).catch(() => undefined);
        throw new FetchError(error ?? "Failed to fetch the public key", {response: res});
    }
    const data = await res.json();
    const cert = data[keyId];
    console.log('cert', cert);
    const spki = crypto.createPublicKey(cert).export({type:'spki', format:'pem'});
    console.log('spki', spki);
    return spki;
}

async function verifyIdToken(idToken, clientId) {
    let issuer = `https://securetoken.google.com/${clientId}`;
    const now = Math.floor(Date.now() / 1000);

    let [encodedHeader, encodedPayload, encodedSignature] = idToken.split('.');

    if (typeof encodedHeader !== 'string' || !encodedHeader) throw new Error();
    if (typeof encodedPayload !== 'string' || !encodedPayload) throw new Error();
    if (typeof encodedSignature !== 'string' || !encodedSignature) throw new Error();
    const header = JSON.parse(new TextDecoder().decode(new Uint8Array(Buffer.from(encodedHeader, 'base64'))));
    const payload = JSON.parse(new TextDecoder().decode(new Uint8Array(Buffer.from(encodedPayload, 'base64'))));
    if (!header) throw new Error();
    if (!payload) throw new Error();

    const cert = await getKey(header.kid);
    const spki = cert.match(/-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----/s)[1].replace(/\s/g, '');
    console.log('spki', spki);
    const algorithm = {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-256"}};
    const key = await crypto.subtle.importKey('spki', new Uint8Array(Buffer.from(spki, 'base64')), algorithm, true, ['verify']);
    console.log('spki', key);

    const signature = new Uint8Array(Buffer.from(encodedSignature, 'base64'));
    const data = new TextEncoder().encode(encodedHeader + '.' + encodedPayload);

    console.log('---crypto.verify---');
    console.log('algorithm', algorithm);
    console.log('key', key);
    //console.log('key', crypto.KeyObject.from(key));
    console.log('signature', signature);
    console.log('data', data);
    const success = await crypto.verify('sha256', data, key, signature);
    console.log('HERE', {success});
    const success2 = await crypto.subtle.verify(algorithm, key, data, signature);
    console.log('HERE', {success2});

    const keyx = await importPublicKey(header.kid);
    const {payload: verifiedPayload} = await jwtVerify(idToken, keyx, {
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

const idToken = `fyJhbGciOiJSUzI1NiIsImtpZCI6ImYyOThjZDA3NTlkOGNmN2JjZTZhZWNhODExNmU4ZjYzMDlhNDQwMjAiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiVGltIEtheSIsImlzcyI6Imh0dHBzOi8vc2VjdXJldG9rZW4uZ29vZ2xlLmNvbS9wY2JhcnQtNjJjYjEiLCJhdWQiOiJwY2JhcnQtNjJjYjEiLCJhdXRoX3RpbWUiOjE3MTI5NjA2OTEsInVzZXJfaWQiOiJ5Umk1YWNLblV2aDE3dXpXTVBidE9kd042WTcyIiwic3ViIjoieVJpNWFjS25VdmgxN3V6V01QYnRPZHdONlk3MiIsImlhdCI6MTcxMzExMDI3MCwiZXhwIjoxNzEzMTEzODcwLCJlbWFpbCI6InRpbWtheUBub3QuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsiZW1haWwiOlsidGlta2F5QG5vdC5jb20iXX0sInNpZ25faW5fcHJvdmlkZXIiOiJwYXNzd29yZCJ9fQ.ccboX-tEFT0n7o9pvrrwRLNg2AepKGgq6TQ1gi4tBwXcH3LJXTcqxT0ktRezAtuMHe8WxpYmI_QRZvi6kqNyB3QYqBydZf6QekgqIoz6HvEJbN5V0ug6uIeEm2ExuaU-qsUoAjUUrTW5FcAXjh6QNKPXhPoLpG-rxVoyRg7K1bVQorRf0tquOaGaOrKiCTuruqnUu62wF46rUS4JhIrbdkGqVPPfkl2tNGt-WbZdse81aUm2kA4qE8D6fIK_nDZk0QM5Ws5UQfTLhu6HHdiyMB9FPEV93UL_zVorMZipYfeasjbS8aEmvDq35PbDtWgwPs5oGK1aHJnuXGI3jTZMWw`;

const [headerJSON, payloadJSON, signature] = idToken.split(/\./);
const header = JSON.parse(atob(headerJSON));
const payload = JSON.parse(atob(payloadJSON));

let decoded = await verifyIdToken(idToken, 'pcbart-62cb1');

console.log({decoded});
