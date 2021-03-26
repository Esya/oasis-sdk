import { eddsa } from 'elliptic'
import { Bip32Ed25519 } from './bip32-ed25519'
import { sign } from 'tweetnacl'

const uint = (buffer: Buffer) => new Uint8Array(buffer);

(async () => {
    const bip39 = require('bip39');
    const seed = bip39.mnemonicToSeedSync(
        'hour robot stove review afford tomato embark kingdom swarm exhibit sibling trip elephant effort minute network harvest mind kite grow gasp evil kiss absent',
    );
    const master = new Uint8Array(seed.slice(0, 32));

    const bip32ed25519 = new Bip32Ed25519();
    const node = bip32ed25519.derive(master, '44/474/0/0/0')

    // console.log(node.A)

    // Try signing and verifying our own pub key - ussing builtin elliptic ed25519
    const xpriv = new Uint8Array(64)
    xpriv.set(node.kL)
    xpriv.set(node.kR, 32)

    const ec = new eddsa('ed25519');
    const ellipticWithPriv = ec.keyFromSecret(Buffer.from(xpriv))
    const msg = Buffer.from('Hello')
    const signature = ellipticWithPriv.sign(msg)

    // Verifies from the private key
    console.log(ellipticWithPriv.verify(msg, signature))

    // Verifies from the public key
    const publicKey = ec.keyFromPublic(ellipticWithPriv.getPublic())
    console.log(publicKey.verify(msg, signature))

    // Initializing Tweetnacl Keypair from our extended priv key
    const tweetNaclWithPriv = sign.keyPair.fromSecretKey(xpriv)

    // The two private keys are the same - returns True
    console.log(tweetNaclWithPriv.secretKey.toString() === uint(ellipticWithPriv.getSecret()).toString())

    // The two public keys are **NOT** the same - returns False
    console.log(tweetNaclWithPriv.publicKey.toString() === uint(ellipticWithPriv.getPublic()).toString())

    // Both keys are 32 bytes as expected
    console.log(tweetNaclWithPriv.publicKey.length)
    console.log(ellipticWithPriv.getPublic().length)

    // Tweetnacl can still validate the message from the pub key generated from elliptic
    console.log( // Returns True
        sign.detached.verify(
            uint(msg),
            uint(signature.toBytes()),
            uint(ellipticWithPriv.getPublic())
        ),
    );

    const tweetNaclSignature = sign.detached(msg, tweetNaclWithPriv.secretKey)

    // Both signatures are 64 bytes signature
    console.log(tweetNaclSignature.length)
    console.log(signature.toBytes().length)
    console.log(Buffer.from(tweetNaclWithPriv.publicKey))

    const pubHexFromNacl = Buffer.from(tweetNaclWithPriv.publicKey).toString('hex')
    const pubHexFromElliptic = Buffer.from(ellipticWithPriv.getPublic()).toString('hex')

    console.log(pubHexFromElliptic.length)
    console.log(pubHexFromElliptic.length)

    const sig = ec.makeSignature(Buffer.from(tweetNaclSignature).toString('hex'))
    const pub = ec.keyFromPublic(pubHexFromNacl, 'hex')
    console.log(ec.verify(msg, sig, pub))

})()