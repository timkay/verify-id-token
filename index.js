
import * as crypto from 'node:crypto';

//const base64ToBuffer = item => new Uint8Array(Buffer.from(item, 'base64url'));
const base64ToBuffer = item => Uint8Array.from(atob(item.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0));

const base64ToText = item => new TextDecoder().decode(base64ToBuffer(item));
const base64JSONToObject = item => JSON.parse(base64ToText(item));
const textToBuffer = item => new TextEncoder().encode(item);
const bufferToText = item => new TextDecoder().decode(item);


function decodeDer(octets, depth = 0) {

    // 30 82 03 1c

    function getClassFormTagLength() {
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
        const data = [...octets.subarray(position, position + length)].map(x => x.toString(16).padStart(2, '0')).join(' ').substr(0, 40);
        return {class: cls, form, tag, length, data};
    }

    let position = 0;

    while (position < octets.length) {
        const result = getClassFormTagLength();
        let value = ''
        if (result.tag === 2) {
            result.type = 'INTEGER';
            value = BigInt(0);
            for (let i = 0; i < result.length; i++) {
                value = value * BigInt(256) + BigInt(octets[position + i]);
            }
        }
        if (result.tag === 3) {
            result.type = 'BIT STRING';
            value = [...octets.subarray(position, position + result.length)].join('');
        }
        if (result.tag === 4) {
            result.type = 'OCTET STRING';
            value = [...octets.subarray(position, position + result.length)].join('');
        }
        if (result.tag === 5) {
            result.type = 'NULL';
        }
        if (result.tag === 6) {
            result.type = 'OBJECT IDENTIFIER';
        }
        if (result.tag === 12) {
            result.type = '???';
            value = bufferToText(octets.subarray(position, position + result.length));
        }
        if (result.tag === 16) {
            result.type = 'SEQUENCE';
        }
        if (result.tag === 17) {
            result.type = 'SET';
            value = [...octets.subarray(position, position + result.length)].join('');
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
        delete result.class;
        const data = result.data;
        delete result.data;
        console.log('  '.repeat(depth), 'ber', value, result, data);
        if (result.form === 1) {
            decodeDer(octets.subarray(position, position + result.length), depth + 1);
        }
        position += result.length;
    }

}

function parseCertificate(byteArray) {
    let asn1 = berToJavaScript(byteArray);
    // if (asn1.cls !== 0 || asn1.tag !== 16 || !asn1.structured) {
    //     throw new Error("This can't be an X.509 certificate. Wrong data type.");
    // }

    var cert = {asn1};  // Include the raw parser result for debugging
    var pieces = berListToJavaScript(asn1.contents);
    // if (pieces.length !== 3) {
    //     throw new Error("Certificate contains more than the three specified children.");
    // }

    cert.tbsCertificate     = parseTBSCertificate(pieces[0]);
    cert.signatureAlgorithm = parseSignatureAlgorithm(pieces[1]);
    cert.signatureValue     = parseSignatureValue(pieces[2]);

    return cert;
}

function parseTBSCertificate(asn1) {
    if (asn1.cls !== 0 || asn1.tag !== 16 || !asn1.structured) {
        throw new Error("This can't be a TBSCertificate. Wrong data type.");
    }
    let tbs = {asn1};  // Include the raw parser result for debugging
    let pieces = berListToJavaScript(asn1.contents);
    if (pieces.length < 7) {
        throw new Error("Bad TBS Certificate. There are fewer than the seven required children.");
    }
    tbs.version = pieces[0];
    tbs.serialNumber = pieces[1];
    tbs.signature = parseAlgorithmIdentifier(pieces[2]);
    tbs.issuer = pieces[3];
    tbs.validity = pieces[4];
    tbs.subject = pieces[5];
    tbs.subjectPublicKeyInfo = parseSubjectPublicKeyInfo(pieces[6]);
    return tbs;  // Ignore optional fields for now
}

function parseSubjectPublicKeyInfo(asn1) {
    if (asn1.cls !== 0 || asn1.tag !== 16 || !asn1.structured) {
        throw new Error("Bad SPKI. Not a SEQUENCE.");
    }
    let spki = {asn1};
    let pieces = berListToJavaScript(asn1.contents);
    if (pieces.length !== 2) {
        throw new Error("Bad SubjectPublicKeyInfo. Wrong number of child objects.");
    }
    spki.algorithm = parseAlgorithmIdentifier(pieces[0]);
    spki.bits = berBitStringValue(pieces[1].contents);
    return spki;
}

function berListToJavaScript(byteArray) {
    let result = new Array();
    let nextPosition = 0;
    while (nextPosition < byteArray.length) {
        let nextPiece = berToJavaScript(byteArray.subarray(nextPosition));
        result.push(nextPiece);
        nextPosition += nextPiece.byteLength;
    }
    return result;
}

function parseSignatureValue(asn1) {
    if (asn1.cls !== 0 || asn1.tag !== 3 || asn1.structured) {
        throw new Error("Bad signature value. Not a BIT STRING.");
    }
    let sig = {asn1};   // Useful for debugging
    sig.bits = berBitStringValue(asn1.contents);
    return sig;
}

function berBitStringValue(byteArray) {
    return {
        unusedBits: byteArray[0],
        bytes: byteArray.subarray(1)
    };
}

let parseSignatureAlgorithm = parseAlgorithmIdentifier;

function parseAlgorithmIdentifier(asn1) {
    if (asn1.cls !== 0 || asn1.tag !== 16 || !asn1.structured) {
        throw new Error("Bad algorithm identifier. Not a SEQUENCE.");
    }
    let alg = {asn1};
    let pieces = berListToJavaScript(asn1.contents);
    if (pieces.length > 2) {
        throw new Error("Bad algorithm identifier. Contains too many child objects.");
    }
    let encodedAlgorithm = pieces[0];
    if (encodedAlgorithm.cls !== 0 || encodedAlgorithm.tag !== 6 || encodedAlgorithm.structured) {
        throw new Error("Bad algorithm identifier. Does not begin with an OBJECT IDENTIFIER.");
    }
    alg.algorithm = berObjectIdentifierValue(encodedAlgorithm.contents);
    if (pieces.length === 2) {
        alg.parameters = {asn1: pieces[1]}; // Don't need this now, so not parsing it
    } else {
        alg.parameters = null;  // It is optional
    }
    return alg;
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
    // console.log('x509', x509);
    // console.log('der', [...der].map(x => x.toString().padStart(3, ' ') + '=0x' + x.toString(16).padStart(2, '0')));
    console.log('der', der);
    console.log(decodeDer(der));

    return;

    const obj = parseCertificate(asn1);
    console.log('contents', bufferToText(obj.contents));
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
