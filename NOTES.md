Just about every web app needs authentication. Lots of providers offer authentication services, including:

* Cloud providers (e.g., Google Auth/Firebase Auth, AWS Cognito, etc.)
* Identity providers (e.g., Okta/auth0)

The process is simple: the web app delegates the authentication process to an authentication provider.
The authentication providers interacts with the users via some user interface and, upon successful authentication, provides an id-token to the web app.
The web app then interacts with its API, to access services on behalf of the user who is identified by the id-token.
The id-token provides proof to the API that the user is who they claim to be.

Before it serves the web app, the API must verify that the id-token is legitimate. Otherwise, a web app could provide a forged id-token and gain access to any user's private information. 

The verification process is simple. The id-token is signed by the provider's private key, and the API verifes its legitimacy using the provider's matching public key:

1. Extract the hash of the public key from the id-token,
2. Fetch the corresponding public key from the provider's service,
3. Use the public key to verify the id-token.

The process seems simple, but the cryptographic community is inclined to make everything as difficult as possible:

1. All platforms have the verify function and the ability to import the public key.
2. Unfortunately, authentication providers don't provide the public key. Instead they publish a certificate that *contains* the public key. Some platforms can extract the public key from the certificate (Chrome), and some can't (Nodejs, Cloudflare). In these cases, extracting the public key requires third-party libraries that are complex, inefficient, and increase the attack surface.
3. The various JavaScript platforms all treat buffers differently. Some use Buffer, some use ArrayBuffer, and some can handle Base64URL directly, while others cannot. The examples all work in some places and not others.

The most common recommendation seems to be, "Go load these third-party libraries to solve the problem." I don't like the idea of relying on numerous third-party libraries to handle authentication, the most important security step.

The id-token has three parts: header, payload, and signature.
The header and signature contain information used to verify the id-token. The payload contains information about the user's identity. It looks like this:

```
{
  aud: "nicework-62cb1",
  auth_time: 1713930400,
  email: "timkay@not.com",
  email_verified: true,
  exp: 1713935563,
  firebase: {identities: {…}, sign_in_provider: 'password'},
  iat: 1713931963,
  iss: "https://securetoken.google.com/nicework-62cb1",
  name: "Tim Kay",
  sub: "yRi6aaKnUvh17uzWMPbtOdwN6Y72",
  user_id: "yRi6aaKnUvh17uzWMPbtOdwN6Y72",
}
```

How does the API know that the id-token is legitimate. Somebody could create an id-token with a payload that claims a certain identity.
How does the server know that the id-token is bogus?

The answer is straight forward. The identity provider signs the id-token using their private key. They also publish their public key at a known URL. The API retrieves the public key, uses it to verify the 
