# Lua NaCl

Lua bindings for [TweetNaCl](http://tweetnacl.cr.yp.to/) by Daniel J. Bernstein, Bernard van Gastel, Wesley Janssen, Tanja Lange, Peter Schwabe and Sjaak Smetsers.

## License

> The author disclaims copyright to this source code.  In place of
> a legal notice, here is a blessing:
>
> * May you do good and not evil.
> * May you find forgiveness for yourself and forgive others.
> * May you share freely, never taking more than you give.

## Authenticated public key encryption

### nacl.box_keypair()

The `nacl.box_keypair` function randomly generates a secret key and a corresponding public key. It returns the public key as first value and the secret key as second value. It guarantees that the secret key has `nacl.box_SECRETKEYBYTES` bytes and that the public key has `nacl.box_PUBLICKEYBYTES` bytes.

### nacl.box(m, n, pk, sk)

The `nacl.box` function encrypts and authenticates a message `m` using the sender’s secret key `sk`, the receiver’s public key `pk`, and a nonce `n`. The `nacl.box` function returns the resulting ciphertext `c`. The function raises an error if `#pk` is not `nacl.box_PUBLICKEYBYTES` or if `#sk` is not `nacl.box_SECRETKEYBYTES` or if `#n` is not `nacl.box_NONCEBYTES`.

A nonce must never be used twice with the same secret key.

### nacl.box_open(c, n, pk, sk)

The `nacl.box_open` function verifies and decrypts a ciphertext `c` using the receiver’s secret key `sk`, the sender’s public key `pk`, and a nonce `n`. The `nacl.box_open` function returns the resulting plaintext `m`.

If the ciphertext fails verification, `nacl.box_open` returns `nil`. The function raises an error if `#pk` is not `nacl.box_PUBLICKEYBYTES` or if `#sk` is not `nacl.box_SECRETKEYBYTES` or if `#n` is not `nacl.box_NONCEBYTES`.

### nacl.box_beforenm(pk, sk)

Applications that send several messages to the same receiver can gain speed by splitting `nacl.box` into two steps, `nacl.box_beforenm` and `nacl.box_afternm`. Similarly, applications that receive several messages from the same sender can gain speed by splitting `nacl.box_open` into two steps, `nacl.box_beforenm` and `nacl.box_open_afternm`.

The `nacl.box_beforenm` function calculates a shared secret from the public key `pk` and the secret key `sk` and returns it. The shared secret always has `nacl.box_BEFORENMBYTES`. The function raises an error if `#pk` is not `nacl.box_PUBLICKEYBYTES` or if `#sk` is not `nacl.box_SECRETKEYBYTES`.

### nacl.afternm(m, n, k)

The `nacl.afternm` function encrypts and authenticates a message `m` using a shared secret `k` and a nonce `n`. The `nacl.afternm` function returns the resulting ciphertext `c`. The function raises an error if `#k` is not `nacl.box_BEFORENMBYTES`. The function also raises an error if `#n` is not `nacl.box_NONCEBYTES`.

A nonce must never be used twice with the same shared secret.

### nacl.afternm_open(c, n, k)

The `nacl.afternm_open` function verifies and decrypts a ciphertext `c` using a secret key `k` and a nonce `n`. The `nacl.afternm_open` function returns the resulting plaintext `m`.

If the ciphertext fails verification, `nacl.afternm_open` returns `nil`. The function raises an error if `#k` is not `nacl.box_BEFORENMBYTES`, or if `#n` is not `nacl.box_NONCEBYTES`.

## Scalar multiplication

### nacl.scalarmult(n, p)

This function multiplies a group element `p` by an integer `n`. It returns the resulting group element `q` of length `nacl.scalarmult_BYTES`. The function raises an error if `#p` is not `nacl.scalarmult_BYTES`. It also raises an error if `#n` is not `nacl.scalarmult_SCALARBYTES`.

### nacl.scalarmult_base(n)

The `nacl.scalarmult_base` function computes the scalar product of a standard group element and an integer `n`. It returns the resulting group element `q` of length `nacl.scalarmult_BYTES`. It raises an exception if `#n` is not `nacl.scalarmult_SCALARBYTES`.

## Signatures

### nacl.sign_keypair()

The `nacl.sign_keypair` function randomly generates a secret key and a corresponding public key. It returns the public key as first value and the secret key as second value. It guarantees that the secret key has `nacl.sign_SECRETKEYBYTES` bytes and that the public key has `nacl.sign_PUBLICKEYBYTES` bytes.

### nacl.sign(m, sk)

The `nacl.sign` function signs a message `m` using the signer’s secret key `sk`. The `nacl.sign` function returns the resulting signed message `sm`. The function raises an error if `#sk` is not `nacl.sign_SECRETKEYBYTES`.

### nacl.sign_open(sm, pk)

The `nacl.sign_open` function verifies the signature in `sm` using the signer’s public key `pk`. The `nacl.sign_open` function returns the message `m`.

If the signature fails verification, `nacl.sign_open` returns `nil`. The function raises an error if `#pk` is not `nacl.sign_PUBLICKEYBYTES`.

## Authenticated secret key encryption

### nacl.secretbox(m, n, k)

The `nacl.secretbox` function encrypts and authenticates a message `m` using a secret key `k` and a nonce `n`. The `nacl.secretbox` function returns the resulting ciphertext `c`. The function raises an error if `#k` is not `nacl.secretbox_KEYBYTES`. The function also raises an error if `#n` is not `nacl.secretbox_NONCEBYTES`.

A nonce must never be used twice with the same key.

### nacl.secretbox_open(c, n, k)

The `nacl.secretbox_open` function verifies and decrypts a ciphertext `c` using a secret key `k` and a nonce `n`. The `nacl.secretbox_open` function returns the resulting plaintext `m`.

If the ciphertext fails verification, `nacl.secretbox_open` returns `nil`. The function raises an error if `#k` is not `nacl.secretbox_KEYBYTES`, or if `#n` is not `nacl.secretbox_NONCEBYTES`.

## Secret key encryption

### nacl.stream(clen, n, k)

The `nacl.stream` function produces a `clen`-byte stream `c` as a function of a secret key `k` and a nonce `n`. The function raises an error if `#k` is not `nacl.stream_KEYBYTES`. It also raises an error if `#n` is not `nacl.stream_NONCEBYTES`.

A nonce must never be used twice with the same key.

### nacl.stream_xor(m, n, k)

The `nacl.stream_xor` function encrypts a message `m` using a secret key `k` and a nonce `n`. The `nacl.stream_xor` function returns the ciphertext `c`. The function raises an error if `#k` is not `nacl.stream_KEYBYTES`. It also raises an error if `#n` is not `nacl.stream_NONCEBYTES`.

The `nacl.stream_xor` function guarantees that the ciphertext has the same length as the plaintext, and is the plaintext xor the output of `nacl.stream`. Consequently `nacl.stream_xor` can also be used to decrypt.

A nonce must never be used twice with the same key.

## Secret key single message authentication

### nacl.onetimeauth(m, k)

The `nacl.onetimeauth` function authenticates a message `m` using a secret key `k`, and returns an authenticator `a`. The authenticator length is always `nacl.onetimeauth_BYTES`. The function raises an error if `#k` is not `nacl.onetimeauth_KEYBYTES`.

### nacl.onetimeauth_verify(a, m, k)

This function checks if `a` is a correct authenticator of a message `m` under the secret key `k`. If this check fails, the function returns `false`, otherwise it returns `true`. If `#k` is not `nacl.onetimeauth_KEYBYTES` or `#a` is not `nacl.onetimeauth_BYTES`, the function raises an error.

## Hashing

### nacl.hash(m)

The `nacl.hash` function hashes a message `m`. It returns `a` hash `h`. The output length `#h` is always `nacl.hash_BYTES`.

## Auxiliary functions

### nacl.randombytes(l)

Returns a string of length `l` filled with random bytes.

### nacl.verify_16(a, b)

Tells if the two 16 byte strings `a` and `b` are equal.

This takes always the same time, regardless of if and where the strings differ.

### nacl.verify_32(a, b)

Tells if the two 32 byte strings `a` and `b` are equal.

This takes always the same time, regardless of if and where the strings differ.
