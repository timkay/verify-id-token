
const debug = 1;

const base64ToBuffer = item => Uint8Array.from(atob(item.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0));
const base64ToText = item => new TextDecoder().decode(base64ToBuffer(item));
const base64JSONToObject = item => JSON.parse(base64ToText(item));
const textToBuffer = item => new TextEncoder().encode(item);
const bufferToText = item => new TextDecoder().decode(item);
// const bufferToBase64 = item => btoa(Array.from(item, ch => String.fromCharCode(ch)).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const bufferToHex = item => [...item].map(x => x.toString(16).padStart(2, '0')).join('');
const bufferToBits = item => [...item].map(x => x.toString(2).padStart(8, '0')).join('');

function decodeDer(octets, depth = 0) {
    let elems = [];
    let position = 0;

    while (position < octets.length) {
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
        const asn1 = octets.subarray(start, position + length);
        // class 0=universal, 1=application, 2=context-specific, 3=private
        const type = [{
            // universal asn.1 tags
            1: 'BOOLEAN', 2: 'INTEGER', 3: 'BIT STRING', 4: 'OCTET STRING', 5: 'NULL', 6: 'OBJECT IDENTIFIER',
            7: 'ObjectDescriptor', 8: 'EXTERNAL', 9: 'REAL', 10: 'ENUMERATED', 11: 'EMBEDDED PDV', 12: 'UTF8String',
            13: 'RELATIVE-OID', 14: 'TIME', 15: '???', 16: 'SEQUENCE', 17: 'SET', 18: 'NUMERIC STRING',
            19: 'PrintableSTring', 20: 'T61String', 21: 'VideotexSTring', 22: 'IA5String', 23: 'UTCTime',
            24: 'GeneralizedTime', 25: 'GraphString', 26: 'VisibleString', 27: 'GeneralString', 28: 'UniversalString',
            29: 'CHARACTER STRING', 30: 'BMPString', 31: 'DATE', 32: 'TIME-OF-DAY', 33: 'DATE-TIME', 34: 'DURATION',
        }, {}, {
            // context-specific tags for x.509 certificates
            0: 'Version', 3: 'Extensions',
        }][cls]?.[tag] ?? `${cls}-${tag}`;

        let value = '';
        let extra;

        if (debug) {
            if (type === 'BOOLEAN') {
                value = !!octets[position];
            }
            if (type === 'INTEGER') {
                value = BigInt(0);
                for (let i = 0; i < length; i++) {
                    value = value * 256n + BigInt(octets[position + i]);
                }
                value = value.toString();
            }
            if (type === 'BIT STRING') {
                extra = octets[position++];
                if (extra !== 0) {
                    console.log('extra bits');
                }
                value = bufferToBits(octets.subarray(position, position + length));
                if (value.length > 69) value = value.slice(0, 69) + '...';
            }
            if (type === 'OCTET STRING') {
                value = bufferToHex(octets.subarray(position, position + length));
            }
        }
        if (type === 'OBJECT IDENTIFIER') {
            const x = Math.min(Math.floor(octets[position] / 40), 2);
            value = x + '.' + (octets[position] - 40 * x);
            let accum = 0;
            for (let i = 1; i < length; i++) {
                accum = (accum << 7) + (octets[position + i] & 0x7f);
                if (!(octets[position + i] & 0x80)) {
                    value += '.' + accum.toString();
                    accum = 0;
                    continue;
                }
            }
            if (accum) value += '.' + accum;
        }
        if (debug) {
            if (type === 'UTF8String') {
                value = bufferToText(octets.subarray(position, position + length));
            }
        }
        if (type === 'UTCTime') {
            value = bufferToText(octets.subarray(position, position + length));
        }
        if (debug) {
            let classTag = `${cls}-${tag}`;
            classTag = '';
            console.log('  '.repeat(depth), classTag, type, `(${length})`, value);
        }
        const node = form === 1? decodeDer(octets.subarray(position, position + length), depth + 1): [];
        Object.assign(node, {type, value, asn1});
        elems.push(node);
        position += length;
    }

    return elems;
}

async function fetchVerifyKey(kid) {

    // check if public key is already cached

    const certificateURL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
    const res = await fetch(certificateURL);
    if (!res.ok) {
        const error = await res.json().then((data) => data.error.message).catch(() => undefined);
        throw new FetchError(error ?? "Failed to fetch the public key", {response: res});
    }
    const x509 = (await res.json())[kid];
    if (!x509) {
        throw new Error('X.509 certificate not found');
    }

    // Get spki directly from certificate
    const der = base64ToBuffer(x509.match(/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s)[1].replace(/\s/g, ''));
    const elems = decodeDer(der);

    if (elems[0][0][2][0].value !== '1.2.840.113549.1.1.5') {
        throw new Error('Certificate is not recognized');
    }

    // 240422194718Z
    const toEpoch = date => Date.parse(date.replace(/^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/,
                                                    (_, y, mo, d, h, m, s) => `20${y}-${mo}-${d}T${h}:${m}:${s}`)) / 1000;

    const validNode = elems[0][0][4];
    const notBefore = toEpoch(validNode[0].value);
    const notAfter = toEpoch(validNode[1].value);

    const keyNode = elems[0][0][6];
    if (keyNode[0][0].value !== '1.2.840.113549.1.1.1') {
        throw new Error('Public key not found in cert');
    }

    // check that it is not before notBefore

    return {spki: keyNode.asn1, notBefore, notAfter};
}

async function getVerifyKey(kid) {
    // check if kid spki is cached
    const {spki, notBefore, notAfter} = await fetchVerifyKey(kid);
    console.log('valid', {notBefore, notAfter});
    // cache spki until notAfter
    return spki;
}

async function verifyIdToken(idToken, clientId) {

    let issuer = `https://securetoken.google.com/${clientId}`;
    let [encodedHeader, encodedPayload, encodedSignature] = idToken.split('.');

    const header = base64JSONToObject(encodedHeader);
    const payload = base64JSONToObject(encodedPayload);

    if (payload.iss != issuer) throw new Error('Token is improperly issued');

    const now = Math.floor(Date.now() / 1000);
    // if (!(payload.iat <= now && now <= payload.exp)) throw new Error('Token is expired');

    const spki = await getVerifyKey(header.kid);

    const algorithm = {name: 'RSASSA-PKCS1-v1_5', hash: {name: "SHA-256"}};
    const key = await crypto.subtle.importKey('spki', spki, algorithm, true, ['verify']);
    const signature = base64ToBuffer(encodedSignature);
    const data = textToBuffer(encodedHeader + '.' + encodedPayload);
    const success = await crypto.subtle.verify(key.algorithm, key, signature, data);

    if (success) return payload;
}

const idToken = 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImEyMzhkZDA0Y2JhYTU4MGIzMDRjODgxZTFjMDA4ZWMyOGZiYmFkZGMiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiVGltIEtheSIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NLWkk1SHFSRlJWdEl1aG5kRnZlSDNXVnBJY2VqUUlfNWhYc0ZHb0RYN0FKTjg9czk2LWMiLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vcGNiYXJ0LTYyY2IxIiwiYXVkIjoicGNiYXJ0LTYyY2IxIiwiYXV0aF90aW1lIjoxNzEyMDM0MjkyLCJ1c2VyX2lkIjoiY1o3UWY2V05VR2V4NHRQc1pxRXV4eFExMk1mMSIsInN1YiI6ImNaN1FmNldOVUdleDR0UHNacUV1eHhRMTJNZjEiLCJpYXQiOjE3MTM5MzAyMzcsImV4cCI6MTcxMzkzMzgzNywiZW1haWwiOiJ0aW1rYXlAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnsiZ29vZ2xlLmNvbSI6WyIxMDY5Mzg1MDE5MjI5MTM3NDM4OTIiXSwiZW1haWwiOlsidGlta2F5QGdtYWlsLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6Imdvb2dsZS5jb20ifX0.q_Q6_JRtv75Rxqbgq4frq4CNxMWZ1v967zLIA3dQFMziL3sOfMgb7mBRf6yZF6ikP5c7D4eohHfbg3PKMk9UV3NoXVy5zoH2WsbzorzAqeSyV2Fl-ElHdgeHRJcRyMlKeWSsxvfu03Ki1ZczzlRzFWIeDCIhbq_3eNEysx6Vn3uRTlBL38lfMdySSR-t2H23LZK262nXw4XnYubVjirItOemY30wX3XGFA67woQpPz209mAjEGeeHQP5j3D25QKF3kJZZGbRRMlJoN_dCVYbcI5JGVzWJqCF1u0hVYlG5b2QTpGg0fC5IAe4hCczUiY7AVCsXjEUSW6HxHUL3QHJAw'

try {
    let verified = await verifyIdToken(idToken, 'pcbart-62cb1');
    console.log({verified});
} catch (err) {
    console.log(err);
}
