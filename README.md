# Verify id-tokens as simply as possible.

This code verifies Firebase Auth id-tokens, so that Firebase Auth can be used with other platforms, such as Cloudflare Workers.

(Work with me to extend this library to other authentication providers. The goal is to keep the code as lean as possible by focusing on the single use case of verifying id-tokens from various authentication providers.)

An id-token is signed by the authentiation provider's private key. This code retrieves the corresponding public key with the following steps:

1. Extract the key-id from the id-token,
2. If the key is not cached, fetch the corresponding `X.509` certificate from the provider, extract the public key from the certificate, cache the public key for next time,
3. Verify the id-token using the public key and the built-in functions `crypto.subtle.importKey()` and `crypto.subtle.verify()`.

The big challenge is that the public key is wrapped in the `X.509` certificate and needs to be extracted. Some platforms have native functions to extract the public key, such as Chrome's `crytpo.importKey()`. (Nodejs and Cloudflare Workers do not have the `crypto` API). The `subtle.crypto.importKey()` does not import `X.509` certificates, leaving developers to rely on third-party libraries, which are typically large, complex, and inefficient. The situation fails the KISS and DRY principles.

This third-party library is designed to handle this single use case as simply and efficiently as possible. KISS

## Usage ##

```
import {verifyIdToken} from 'verify-id-token';
...
const payload = verifyIdToken(idToken, projectId);
console.log(payload)
```

If `idToken` verified, then payload will contain the user metadata (displayName, email, etc.). If verification fails, an error will be thrown.

The fetched `X.509` certificate is validated before use. If the certificate is expired, in the wrong format, etc., an error will be thrown.
The `idToken` is validated before being verified. If the token is expired, in the wrong format, or for the wrong project, an error will be thrown.

## Example ##

The following code demonstrates using `user.getIdToken()` to get the id-token and then verify it. This code is for demonstration purposes only. In practice, the id-token would be sent to the API, where the API would verify the id-token, and thus know that the user is who they claim to be.

```
firebase.auth().onAuthStateChanged(async user => {
    if (user) {
        user.getIdToken(/* forceRefresh */ true)
        .then(async token => {
            console.log({token});
            const payload = await verifyIdToken(token, 'tulip-62cb1');
            console.log(payload);
        })
    }
});
```

## Technical Notes ##

It is possible that `crypto.subtle.importKey()` will import `X.509` certificates, and I wasn't able to figure out how. If so, then this library is not necessary. Feedback, please!

X.509 certificates are encoded in the `ASN.1` protocol, which is decoded by this library. The public key is then directly extracted.

An alternate strategy was suggested by Claude AI: simply identify the start of the public key by the sequence of bytes, and then extract that sequence from the `X.509` certificate. Such a shortcut is brittle and also does not extract the key's `valid` timestamps.

A debug setting causes the `X.509` certificate's `ASN.1` data to be dumped.
