// bcrypt init / Eksblowfish setup — P-array + S-box initialization

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
    cost: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

const P: array<u32, 18> = array(
    0x243f6a88u,0x85a308d3u,0x13198a2eu,0x03707344u,0xa4093822u,0x299f31d0u,
    0x082efa98u,0xec4e6c89u,0x452821e6u,0x38d01377u,0xbe5466cfu,0x34e90c6cu,
    0xc0ac29b7u,0xc97c50ddu,0x3f84d5b5u,0xb5470917u,0x9216d5d9u,0x8979fb1bu,
);

const SBOX: array<u32, 1024> = array(
    0xd1310ba6u,0x98dfb5acu,0x2ffd72dbu,0xd01adfb7u,0xb8e1afedu,0x6a267e96u,
    0xba7c9045u,0xf12c7f99u,0x24a19947u,0xb3916cf7u,0x0801f2e2u,0x858efc16u,
    0x636920d8u,0x71574e69u,0xa458fea3u,0xf4933d7eu,0x0d95748fu,0x728eb658u,
    0x718bcd58u,0x82154aeeu,0x7b54a41du,0xc25a59b5u,0x9c30d539u,0x2af26013u,
    0xc5d1b023u,0x286085f0u,0xca417918u,0xb8db38efu,0x8e79dcb0u,0x603a180eu,
    0x6c9e0e8bu,0xb01e8a3eu,0xd71577c1u,0xbd314b27u,0x78af2fdau,0x55605c60u,
    0xe65525f3u,0xaa55ab94u,0x57489862u,0x63e81440u,0x55ca396au,0x2aab10b6u,
    0xb4cc5c34u,0x1141e8ceu,0xa15486afu,0x7c72e993u,0xb3ee1411u,0x636fbc2au,
    0x2ba9c55du,0x741831f6u,0xce5c3e16u,0x9b87931eu,0xafd6ba33u,0x6c24cf5cu,
    0x7a325381u,0x28958677u,0x3b8f4898u,0x6b4bb9afu,0xc4bfe81bu,0x66282193u,
    0x61d809ccu,0xfb21a991u,0x487cac60u,0x5dec8032u,0xef845d5du,0xe98575b1u,
    0xdc262302u,0xeb651b88u,0x23893e81u,0xd396acc5u,0x0f6d6ff3u,0x83f44239u,
    0x2e0b4482u,0xa4842004u,0x69c8f04au,0x9e1f9b5eu,0x21c66842u,0xf6e96c9au,
    0x670c9c61u,0xabd388f0u,0x6a51a0d2u,0xd8542f68u,0x960fa728u,0xab5133a3u,
    0x6eef0b6cu,0x137a3be4u,0xba3bf050u,0x7efb2a98u,0xa1f1651du,0x39af0176u,
    0x66ca593eu,0x82430e88u,0x8cee8619u,0x456f9fb4u,0x7d84a5c3u,0x3b8b5ebeu,
);

fn blowfish_encrypt(L: ptr<function, u32>, R: ptr<function, u32>, p: ptr<function, array<u32, 18>>, s: ptr<function, array<u32, 1024>>) {
    var l = *L; var r = *R;
    for (var i: u32 = 0u; i < 16u; i++) {
        l ^= (*p)[i];
        var t = (*s)[u32(l >> 24u)] + (*s)[256u + u32((l >> 16u) & 0xffu)];
        t ^= (*s)[512u + u32((l >> 8u) & 0xffu)];
        t += (*s)[768u + u32(l & 0xffu)];
        r ^= t;
        let tmp = l; l = r; r = tmp;
    }
    let tmp = l; l = r; r = tmp;
    r ^= (*p)[16u];
    l ^= (*p)[17u];
    *L = l; *R = r;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if (idx >= config.pcount) { return; }

    var P_local: array<u32, 18> = P;
    var S_local: array<u32, 1024> = SBOX;

    var pw: array<u8, 64>;
    let base = idx * 16u;
    for (var i: u32 = 0u; i < 64u; i++) {
        pw[i] = u8((input[base + i / 4u] >> ((i % 4u) * 8u)) & 0xffu);
    }
    var pwlen: u32 = 0u;
    for (var i: u32 = 0u; i < 64u; i++) { if (pw[i] == 0u) { pwlen = i; break; } }
    if (pwlen == 0u && pw[0] != 0u) { pwlen = 64u; }

    var j: u32 = 0u;
    for (var i: u32 = 0u; i < 18u; i++) {
        var key_word: u32 = 0u;
        for (var k: u32 = 0u; k < 4u; k++) {
            key_word = (key_word << 8u) | u32(pw[j % pwlen]);
            j++;
        }
        P_local[i] ^= key_word;
    }

    var L: u32 = 0u; var R: u32 = 0u;
    for (var i: u32 = 0u; i < 9u; i++) {
        blowfish_encrypt(&L, &R, &P_local, &S_local);
        P_local[i * 2u] = L;
        P_local[i * 2u + 1u] = R;
    }

    let cost_iter = 1u << config.cost;
    for (var c: u32 = 0u; c < cost_iter; c++) {
        for (var i: u32 = 0u; i < 9u; i++) {
            blowfish_encrypt(&L, &R, &P_local, &S_local);
            P_local[i * 2u] = L;
            P_local[i * 2u + 1u] = R;
        }
        for (var i: u32 = 0u; i < 512u; i++) {
            blowfish_encrypt(&L, &R, &P_local, &S_local);
            S_local[i * 2u] = L;
            S_local[i * 2u + 1u] = R;
        }
    }

    let out_base = idx * 520u;
    for (var i: u32 = 0u; i < 18u; i++) { output[out_base + i] = P_local[i]; }
    for (var i: u32 = 0u; i < 1024u; i++) { output[out_base + 18u + i] = S_local[i]; }
}
