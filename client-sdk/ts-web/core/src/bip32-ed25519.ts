import { eddsa } from 'elliptic';
import { sha512 } from 'js-sha512';
import { sha256 } from 'js-sha256';
import * as BN from 'bn.js';

export interface Ed25519Node {
    kL: Uint8Array;
    kR: Uint8Array;
    A: Buffer;
    c: Uint8Array;
}

// Shorthand for Bignumber instanciation
const bn = (i: number | string | Uint8Array, base?: number, endianness?: 'le' | 'be') =>
    new BN(i, base, endianness);

export class Bip32Ed25519 {
    private eddsa: eddsa;

    // Base point
    private bp: eddsa.Point;

    // Prime-order of the basepoint
    private l: BN;

    constructor() {
        this.eddsa = new eddsa('ed25519');

        // Calculate the basepoint Y coordinate
        const two = bn(2);
        const q = two.pow(bn(255)).sub(bn(19));

        const five = bn(5);
        const by = five.mod(q).invm(q).mul(bn(4)).mod(q);

        // Derive the point from Y
        this.bp = this.eddsa.curve.pointFromY(by);

        // Calculate the prime order of the basepoint
        this.l = two.pow(bn(252)).add(bn('27742317777372353535851937790883648493'));
    }

    /**
     *
     * @param masterkey 32 bytes Uint8array
     */
    public root_key(masterkey: Uint8Array): Ed25519Node {
        if (masterkey.length != 32)
            throw 'master_secret must be 32 bytes (a Uint8Array of size 32)';

        const k = new Uint8Array(sha512.arrayBuffer(masterkey));
        const kL = k.slice(0, 32),
            kR = k.slice(32);

        if (kL[31] & 0b00100000) {
            console.log('Invalid last byte');
            return null;
        }

        // clear lowest three bits of the first byte
        kL[0] = this.clearBit(kL[0], 0b00000111);
        // clear highest bit of the last byte
        kL[31] = this.clearBit(kL[31], 0b10000000);
        // set second highest bit of the last byte
        kL[31] = this.setBit(kL[31], 0b01000000);

        // Get the public key
        const A = this.eddsa.encodePoint(this.bp.mul(bn(kL, 10, 'le')));

        const chaincodePayload = this.concatUint8Arrays([new Uint8Array([1]), masterkey]);
        const c = new Uint8Array(sha256.arrayBuffer(chaincodePayload));

        return {kL, kR, A, c};
    }

    public derive(master: Uint8Array, path: string): Ed25519Node {
        var root = this.root_key(master);
        var node = root;
        const chain = path.split('/');

        for (let i = 0; i < chain.length; i++) {
            let index;
            if (!chain[i]) continue;
            if (chain[i].endsWith("'"))
                // Hardened offset ; @todo 0x8...
                index = bn(chain[i].slice(0, -1)).add(bn(2).pow(bn(31)));
            // Non hardened path
            else index = bn(chain[i]);

            node = this.deriveChild(node, index);
        }
        return node;
    }

    public deriveChild(node: Ed25519Node, index: BN): Ed25519Node {
        const kLP = node.kL,
            kRP = node.kR,
            AP = node.A,
            cP = node.c;

        if (!(index.gte(bn(0)) && index.lt(bn(2).pow(bn(32))))) {
            throw 'Index i must be between 0 and 2^32 - 1, inclusive';
        }

        const i_bytes = index.toBuffer('le', 4);

        let Z: Uint8Array, c: Uint8Array;
        if (index.lt(bn(2).pow(bn(31)))) {
            // regular child
            Z = this.hmacSha512(
                this.concatUint8Arrays([new Uint8Array([2]), new Uint8Array(AP), i_bytes]),
                cP,
            );
            c = this.hmacSha512(
                this.concatUint8Arrays([new Uint8Array([3]), new Uint8Array(AP), i_bytes]),
                cP,
            ).slice(32);
        } else {
            // hardened child
            Z = this.hmacSha512(
                this.concatUint8Arrays([new Uint8Array([0]), kLP, kRP, i_bytes]),
                cP,
            );
            c = this.hmacSha512(
                this.concatUint8Arrays([new Uint8Array([1]), kLP, kRP, i_bytes]),
                cP,
            ).slice(32);
        }

        const ZL = Z.slice(0, 28),
            ZR = Z.slice(32);

        const kLn = bn(ZL, 10, 'le').mul(bn(8)).add(bn(kLP, 10, 'le'));

        // "If kL is divisible by the base order n, discard the child."
        // - "BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace" (https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view)
        if (kLn.mod(this.l).eq(bn(0))) {
            return null;
        }

        const kRn = bn(ZR, 10, 'le')
            .add(bn(kRP, 10, 'le'))
            .mod(bn(2).pow(bn(256)));

        const kL = new Uint8Array(kLn.toBuffer('le', 32));
        const kR = new Uint8Array(kRn.toBuffer('le', 32));

        const A = this.eddsa.encodePoint(this.bp.mul(bn(kL, 10, 'le')));

        return {kL, kR, A, c};
    }

    private hmacSha512(message: Uint8Array, key: Uint8Array): Uint8Array {
        // Invalid types for key inside js-sha512 - See https://github.com/emn178/js-sha512/issues/18
        const hash = sha512.hmac
            .create(key as any)
            .update(message)
            .arrayBuffer();
        return new Uint8Array(hash);
    }

    private clearBit(byte: number, mask: number): number {
        return byte & ~mask;
    }

    private setBit(byte: number, mask: number): number {
        return byte | mask;
    }

    private concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
        let length = 0;

        arrays.forEach((item) => {
            length += item.length;
        });

        let mergedArray = new Uint8Array(length);
        let offset = 0;

        arrays.forEach((item) => {
            mergedArray.set(item, offset);
            offset += item.length;
        });

        return mergedArray;
    }
}
