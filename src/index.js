/*
 * Verify id-tokens as simply as possible.
 *
 * This code verifies Firebase Auth id-tokens, so that Firebase Auth
 * can be used with other platforms, such as Cloudflare Workers.
 */

/* Settings:
 *   tokenExp - Check for token expiration and throw an error.
 *              Turned off for testing because the test id-token
 *              will be expired.
 */

export const setting = {
    tokenExp: true,             // check for token expiration
};

const base64ToBuffer = item => Uint8Array.from(atob(item.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0));
const base64ToText = item => new TextDecoder().decode(base64ToBuffer(item));
const base64JSONToObject = item => JSON.parse(base64ToText(item));
const textToBuffer = item => new TextEncoder().encode(item);
// const bufferToText = item => new TextDecoder().decode(item);
// const bufferToBase64 = item => btoa(Array.from(item, ch => String.fromCharCode(ch)).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
// const bufferToHex = item => [...item].map(x => x.toString(16).padStart(2, '0')).join('');
// const bufferToBits = item => [...item].map(x => x.toString(2).padStart(8, '0')).join('');

async function fetchVerifyJWK(kid) {
    console.log(`fetchVerifyJWK(${kid})`);
    const res = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
    const data = await res.json();
    return data.keys.find(key => key.kid === kid);
}

async function getVerifyJWK(kid) {
    const cache = typeof caches !== 'undefined' && caches.default;
    if (!cache) return await fetchVerifyJWK(kid);
    console.log(`getVerifyJWK(${kid})`);
    const url = `https://verify-id-token/google/3/${kid}`;
    const res = await cache.match(url);
    if (res) return await res.json();
    const key = await fetchVerifyJWK(kid);
    context.waitUntil(cache.put(url, new Response(JSON.stringify(key)), {headers: {'Cache-Control': 'max-age: 10'}}));
    return key;
}

export async function verifyIdToken(idToken, clientId) {
    let [encodedHeader, encodedPayload, encodedSignature] = idToken.split('.');

    const header = base64JSONToObject(encodedHeader);
    const payload = base64JSONToObject(encodedPayload);

    if (clientId && payload.iss !== `https://securetoken.google.com/${clientId}`) throw new Error('Token is improperly issued');

    const now = Math.floor(Date.now() / 1000);
    if (setting.tokenExp && !(payload.iat <= now && now <= payload.exp)) throw new Error('Token is expired');

    const algorithm = {name: 'RSASSA-PKCS1-v1_5', hash: {name: "SHA-256"}};
    const signature = base64ToBuffer(encodedSignature);
    const data = textToBuffer(encodedHeader + '.' + encodedPayload);

    const jwk = await getVerifyJWK(header.kid);
    const key = await crypto.subtle.importKey('jwk', jwk, algorithm, false, ['verify']);
    const success = await crypto.subtle.verify(key.algorithm, key, signature, data);
    if (success === true) return payload;

    throw new Error('Token fails to verify');
}

export default {setting, verifyIdToken};
