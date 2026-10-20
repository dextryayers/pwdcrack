// SHA-512, one candidate per invocation, with every 64 bit value held as two
// u32 halves. WGSL has no baseline 64 bit integer, and wgpu 26 does not expose a
// feature that would enable one, so pairs are the portable form.
//
// Layout: see md5.wgsl. A message of at most 64 bytes pads into a single 128 byte
// block, which is the only size this kernel accepts.

struct Candidate {
    data: array<u32, 16>,
    len: u32,
}

struct U64 {
    hi: u32,
    lo: u32,
}

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<u32>;
@group(0) @binding(2) var<storage, read> expected: array<u32, 16>;
@group(0) @binding(3) var<uniform> count: u32;

const K: array<U64, 80> = array(
    U64(0x428a2f98u, 0xd728ae22u), U64(0x71374491u, 0x23ef65cdu),
    U64(0xb5c0fbcfu, 0xec4d3b2fu), U64(0xe9b5dba5u, 0x8189dbbcu),
    U64(0x3956c25bu, 0xf348b538u), U64(0x59f111f1u, 0xb605d019u),
    U64(0x923f82a4u, 0xaf194f9bu), U64(0xab1c5ed5u, 0xda6d8118u),
    U64(0xd807aa98u, 0xa3030242u), U64(0x12835b01u, 0x45706fbeu),
    U64(0x243185beu, 0x4ee4b28cu), U64(0x550c7dc3u, 0xd5ffb4e2u),
    U64(0x72be5d74u, 0xf27b896fu), U64(0x80deb1feu, 0x3b1696b1u),
    U64(0x9bdc06a7u, 0x25c71235u), U64(0xc19bf174u, 0xcf692694u),
    U64(0xe49b69c1u, 0x9ef14ad2u), U64(0xefbe4786u, 0x384f25e3u),
    U64(0x0fc19dc6u, 0x8b8cd5b5u), U64(0x240ca1ccu, 0x77ac9c65u),
    U64(0x2de92c6fu, 0x592b0275u), U64(0x4a7484aau, 0x6ea6e483u),
    U64(0x5cb0a9dcu, 0xbd41fbd4u), U64(0x76f988dau, 0x831153b5u),
    U64(0x983e5152u, 0xee66dfabu), U64(0xa831c66du, 0x2db43210u),
    U64(0xb00327c8u, 0x98fb213fu), U64(0xbf597fc7u, 0xbeef0ee4u),
    U64(0xc6e00bf3u, 0x3da88fc2u), U64(0xd5a79147u, 0x930aa725u),
    U64(0x06ca6351u, 0xe003826fu), U64(0x14292967u, 0x0a0e6e70u),
    U64(0x27b70a85u, 0x46d22ffcu), U64(0x2e1b2138u, 0x5c26c926u),
    U64(0x4d2c6dfcu, 0x5ac42aedu), U64(0x53380d13u, 0x9d95b3dfu),
    U64(0x650a7354u, 0x8baf63deu), U64(0x766a0abbu, 0x3c77b2a8u),
    U64(0x81c2c92eu, 0x47edaee6u), U64(0x92722c85u, 0x1482353bu),
    U64(0xa2bfe8a1u, 0x4cf10364u), U64(0xa81a664bu, 0xbc423001u),
    U64(0xc24b8b70u, 0xd0f89791u), U64(0xc76c51a3u, 0x0654be30u),
    U64(0xd192e819u, 0xd6ef5218u), U64(0xd6990624u, 0x5565a910u),
    U64(0xf40e3585u, 0x5771202au), U64(0x106aa070u, 0x32bbd1b8u),
    U64(0x19a4c116u, 0xb8d2d0c8u), U64(0x1e376c08u, 0x5141ab53u),
    U64(0x2748774cu, 0xdf8eeb99u), U64(0x34b0bcb5u, 0xe19b48a8u),
    U64(0x391c0cb3u, 0xc5c95a63u), U64(0x4ed8aa4au, 0xe3418acbu),
    U64(0x5b9cca4fu, 0x7763e373u), U64(0x682e6ff3u, 0xd6b2b8a3u),
    U64(0x748f82eeu, 0x5defb2fcu), U64(0x78a5636fu, 0x43172f60u),
    U64(0x84c87814u, 0xa1f0ab72u), U64(0x8cc70208u, 0x1a6439ecu),
    U64(0x90befffau, 0x23631e28u), U64(0xa4506cebu, 0xde82bde9u),
    U64(0xbef9a3f7u, 0xb2c67915u), U64(0xc67178f2u, 0xe372532bu),
    U64(0xca273eceu, 0xea26619cu), U64(0xd186b8c7u, 0x21c0c207u),
    U64(0xeada7dd6u, 0xcde0eb1eu), U64(0xf57d4f7fu, 0xee6ed178u),
    U64(0x06f067aau, 0x72176fbau), U64(0x0a637dc5u, 0xa2c898a6u),
    U64(0x113f9804u, 0xbef90daeu), U64(0x1b710b35u, 0x131c471bu),
    U64(0x28db77f5u, 0x23047d84u), U64(0x32caab7bu, 0x40c72493u),
    U64(0x3c9ebe0au, 0x15c9bebcu), U64(0x431d67c4u, 0x9c100d4cu),
    U64(0x4cc5d4beu, 0xcb3e42b6u), U64(0x597f299cu, 0xfc657e2au),
    U64(0x5fcb6fabu, 0x3ad6faecu), U64(0x6c44198cu, 0x4a475817u),
);

fn bswap(x: u32) -> u32 {
    return (x >> 24u) | ((x >> 8u) & 0xff00u) | ((x << 8u) & 0xff0000u) | (x << 24u);
}

fn add(a: U64, b: U64) -> U64 {
    let lo = a.lo + b.lo;
    let carry = select(0u, 1u, lo < a.lo);
    return U64(a.hi + b.hi + carry, lo);
}

fn xor(a: U64, b: U64) -> U64 {
    return U64(a.hi ^ b.hi, a.lo ^ b.lo);
}

fn and(a: U64, b: U64) -> U64 {
    return U64(a.hi & b.hi, a.lo & b.lo);
}

fn not(a: U64) -> U64 {
    return U64(~a.hi, ~a.lo);
}

fn shr(a: U64, n: u32) -> U64 {
    if (n == 0u) {
        return a;
    } else if (n < 32u) {
        return U64(a.hi >> n, (a.lo >> n) | (a.hi << (32u - n)));
    } else if (n == 32u) {
        return U64(0u, a.hi);
    }
    return U64(0u, a.hi >> (n - 32u));
}

fn rotr(a: U64, n: u32) -> U64 {
    if (n == 0u) {
        return a;
    } else if (n < 32u) {
        return U64((a.hi >> n) | (a.lo << (32u - n)), (a.lo >> n) | (a.hi << (32u - n)));
    } else if (n == 32u) {
        return U64(a.lo, a.hi);
    }
    let m = n - 32u;
    return U64((a.lo >> m) | (a.hi << (32u - m)), (a.hi >> m) | (a.lo << (32u - m)));
}

fn compress(st: ptr<function, array<U64, 8>>, m: array<U64, 16>) {
    var w: array<U64, 80>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        w[i] = m[i];
    }
    for (var i = 16u; i < 80u; i = i + 1u) {
        let s0 = xor(xor(rotr(w[i - 15u], 1u), rotr(w[i - 15u], 8u)), shr(w[i - 15u], 7u));
        let s1 = xor(xor(rotr(w[i - 2u], 19u), rotr(w[i - 2u], 61u)), shr(w[i - 2u], 6u));
        w[i] = add(add(add(w[i - 16u], s0), w[i - 7u]), s1);
    }

    var a = (*st)[0];
    var b = (*st)[1];
    var c = (*st)[2];
    var d = (*st)[3];
    var e = (*st)[4];
    var f = (*st)[5];
    var g = (*st)[6];
    var h = (*st)[7];

    for (var i = 0u; i < 80u; i = i + 1u) {
        let s1 = xor(xor(rotr(e, 14u), rotr(e, 18u)), rotr(e, 41u));
        let ch = xor(and(e, f), and(not(e), g));
        let t1 = add(add(add(add(h, s1), ch), K[i]), w[i]);
        let s0 = xor(xor(rotr(a, 28u), rotr(a, 34u)), rotr(a, 39u));
        let maj = xor(xor(and(a, b), and(a, c)), and(b, c));
        let t2 = add(s0, maj);
        h = g;
        g = f;
        f = e;
        e = add(d, t1);
        d = c;
        c = b;
        b = a;
        a = add(t1, t2);
    }

    (*st)[0] = add((*st)[0], a);
    (*st)[1] = add((*st)[1], b);
    (*st)[2] = add((*st)[2], c);
    (*st)[3] = add((*st)[3], d);
    (*st)[4] = add((*st)[4], e);
    (*st)[5] = add((*st)[5], f);
    (*st)[6] = add((*st)[6], g);
    (*st)[7] = add((*st)[7], h);
}

fn compare(st: array<U64, 8>) -> bool {
    for (var i = 0u; i < 8u; i = i + 1u) {
        if (bswap(st[i].hi) != expected[2u * i] || bswap(st[i].lo) != expected[2u * i + 1u]) {
            return false;
        }
    }
    return true;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if (idx >= count) {
        return;
    }

    let c = candidates[idx];

    var w: array<u32, 32>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        w[i] = c.data[i];
    }
    for (var i = 16u; i < 32u; i = i + 1u) {
        w[i] = 0u;
    }
    let byte_index = c.len / 4u;
    let byte_offset = c.len % 4u;
    let keep = (1u << (byte_offset * 8u)) - 1u;
    w[byte_index] = (w[byte_index] & keep) | (0x80u << (byte_offset * 8u));
    // 128 bit length field: the high 96 bits are zero for a message this short.
    w[31] = c.len * 8u;

    var m: array<U64, 16>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        m[i] = U64(bswap(w[2u * i]), bswap(w[2u * i + 1u]));
    }

    var st = array<U64, 8>(
        U64(0x6a09e667u, 0xf3bcc908u), U64(0xbb67ae85u, 0x84caa73bu),
        U64(0x3c6ef372u, 0xfe94f82bu), U64(0xa54ff53au, 0x5f1d36f1u),
        U64(0x510e527fu, 0xade682d1u), U64(0x9b05688cu, 0x2b3e6c1fu),
        U64(0x1f83d9abu, 0xfb41bd6bu), U64(0x5be0cd19u, 0x137e2179u),
    );

    compress(&st, m);

    results[idx] = select(0u, 1u, compare(st));
}
