
import * as crypto from 'node:crypto';

async function verifyIdToken(idToken, clientId) {

    //const base64ToBuffer = item => new Uint8Array(Buffer.from(item, 'base64url'));
    const base64ToBuffer = item => Uint8Array.from(atob(item.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0));

    const base64ToText = item => new TextDecoder().decode(base64ToBuffer(item));
    const base64JSONToObject = item => JSON.parse(base64ToText(item));
    const textToBuffer = item => new TextEncoder().encode(item);


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
    // console.log('x509', x509);
    // const pem = x509.match(/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s)[1].replace(/\s/g, '');
    // console.log('pem', pem);
    // console.log('pem', base64ToText(pem));

    // const key1 = new crypto.X509Certificate(x509).publicKey;
    // console.log('key1', key1);

    const cert = await crypto.createPublicKey(x509).export({type:'spki', format:'pem'});
    console.log('cert', cert);
    const spki = cert.match(/-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----/s)[1].replace(/\s/g, '');
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
    console.log(err.message);
}
