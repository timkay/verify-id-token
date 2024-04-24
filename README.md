Just about every web app needs authentication. Lots of providers offer authentication services, including:

* Cloud providers (e.g., Google Auth/Firebase Auth, AWS Cognito, etc.)
* Identity providers (e.g., Okta/auth0)

The process is simple: the web app delegates the authentication process to an authentication provider.
The authentication providers interacts with the users via some user interface and, upon successful authentication, provides an id-token to the web app.
The web app then interacts with the app's API, which provides services to the app on behalf of the user, who is identified by the id-token.
The id-token provides proof to the API that the user is who they claim to be.

Before it serves the web app, the API needs to verify that the id-token is legitimate. Otherwise, a web app could provide a forgery and access to any user's private information. 

The verification process is simple. The id-token is signed by the provider's private key. Anybody can pull the provider's corresponding public key, and use that key to verify the token.

1. Extrace the hash of the public key from the id-token,
2. Fetch the corresponding public key from the provider's service,
3. Use the public key to verify the id-token.

It seems simple, but the cryptographic community seems inclined to make everything as difficult as possible.

1. The authentication provider doesn't publish the public key. Instead they publish a certificate that contains the public key.
2. Each JavaScript platform (browser, Nodejs, Functions) implements different native functions. They all seem to have the verify function, and they have the ability to import they public key, but they can't all import the the certificate directly.
3. The various JavaScript platforms all treat buffers differently. Some use Buffer, some use ArrayBuffer, and some can handle Base64URL directly, while others cannot. So much for standards.

The most common recommendation seems to be, "Go load these third-party libraries to solve the problem." I don't like the idea 

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
