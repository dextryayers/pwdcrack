// bcrypt compute shader — cost configurable via uniform
// Blowfish-based with 4KB S-boxes (1024 entries × 4 bytes)

struct Candidate {
    password: array<u32, 16>,
    len: u32,
}

struct HashResult {
    found: u32,
    idx: u32,
    digest: vec4<u32>,
}

struct BcryptConfig {
    cost: u32,          // 4..31 (2^cost rounds)
    salt: array<u32, 4>, // 16-byte salt
}

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<HashResult>;
@group(0) @binding(2) var<storage, read> target: array<u32, 8>;
@group(0) @binding(3) var<uniform> count: u32;
@group(0) @binding(4) var<uniform> config: BcryptConfig;

const P_ORIG: array<u32, 18> = array(
    0x243f6a88u, 0x85a308d3u, 0x13198a2eu, 0x03707344u,
    0xa4093822u, 0x299f31d0u, 0x082efa98u, 0xec4e6c89u,
    0x452821e6u, 0x38d01377u, 0xbe5466cfu, 0x34e90c6cu,
    0xc0ac29b7u, 0xc97c50ddu, 0x3f84d5b5u, 0xb5470917u,
    0x9216d5d9u, 0x8979fb1bu,
);

const S_ORIG: array<u32, 1024> = array(
    // S-box 0
    0xd1310ba6u, 0x98dfb5acu, 0x2ffd72dbu, 0xd01adfb7u,
    0xb8e1afedu, 0x6a267e96u, 0xba7c9045u, 0xf12c7f99u,
    0x24a19947u, 0xb3916cf7u, 0x0801f2e2u, 0x858efc16u,
    0x636920d8u, 0x71574e69u, 0xa458fea3u, 0xf4933d7eu,
    0x0d95748fu, 0x728eb658u, 0x718bcd58u, 0x82154aeeu,
    0x7b54a41du, 0xc25a59b5u, 0x9c30d539u, 0x2af26013u,
    0xc5d1b023u, 0x286085f0u, 0xca417918u, 0xb8db38efu,
    0x8e79dcb0u, 0x603a180eu, 0x6c9e0e8bu, 0xb01e8a3eu,
    // S-box 1
    0xd71577c1u, 0xbd314b27u, 0x78af2fdau, 0x55605c60u,
    0xe65525f3u, 0xaa55ab94u, 0x57489862u, 0x63e81440u,
    0x55ca396au, 0x2aab10b6u, 0xb4cc5c34u, 0x1141e8ceu,
    0xa15486afu, 0x7c72e993u, 0xb3ee1411u, 0x636fbc2au,
    0x2ba9c55du, 0x741831f6u, 0xce5c3e16u, 0x9b87931eu,
    0xafd6ba33u, 0x6c24cf5cu, 0x7a325381u, 0x28958677u,
    0x3b8f4898u, 0x6b4bb9afu, 0xc4bfe81bu, 0x66282193u,
    0x61d809ccu, 0xfb21a991u, 0x487cac60u, 0x5dec8032u,
    // S-box 2
    0xef845d5du, 0xe98575b1u, 0xdc262302u, 0xeb651b88u,
    0x23893e81u, 0xd396acc5u, 0x0f6d6ff3u, 0x83f44239u,
    0x2e0b4482u, 0xa4842004u, 0x69c8f04au, 0x9e1f9b5eu,
    0x21c66842u, 0xf6e96c9au, 0x670c9c61u, 0xabd388f0u,
    0x6a51a0d2u, 0xd8542f68u, 0x960fa728u, 0xab5133a3u,
    0x6eef0b6cu, 0x137a3be4u, 0xba3bf050u, 0x7efb2a98u,
    0xa1f1651du, 0x39af0176u, 0x66ca593eu, 0x82430e88u,
    0x8cee8619u, 0x456f9fb4u, 0x7d84a5c3u, 0x3b8b5ebeu,
    // S-box 3
    0xe06f75d8u, 0x85c12073u, 0x401a449fu, 0x56c16aa6u,
    0x4ed3aa62u, 0x363f7706u, 0x1bfedf72u, 0x429b023du,
    0x37d0d724u, 0xd00a1248u, 0xdb0fead3u, 0x49f1c09bu,
    0x075372c9u, 0x80991b7bu, 0x25d479d8u, 0xf6e8def7u,
    0xe3fe501au, 0xb6794c3bu, 0x976ce0bdu, 0x04c006bau,
    0xc1a94fb6u, 0x409f60c4u, 0x5e5c9ec2u, 0x196a2463u,
    0x68fb6fafu, 0x3e6c53b5u, 0x1339b2ebu, 0x3b52ec6fu,
    0x6dfc511fu, 0x9b30952cu, 0xcc814544u, 0xaf5ebd09u,
    0xbee3d004u, 0xde334afdu, 0x660f2807u, 0x192e4bb3u,
    0xc0cba857u, 0x45c8740fu, 0xd20b5f39u, 0xb9d3fbdbu,
    0x5579c0bdu, 0x1a60320au, 0xd6a100c6u, 0x402c7279u,
    0x679f25feu, 0xfb1fa3ccu, 0x8ea5e9f8u, 0xdb3222f8u,
    0x3c7516dfu, 0xfd616b15u, 0x2f501ec8u, 0xad0552abu,
    0x323db5fau, 0xfd238760u, 0x53317b48u, 0x3e00df82u,
    0x9e5c57bbu, 0xca6f8ca0u, 0x1a87562eu, 0xdf1769dbu,
    0xd542a8f6u, 0x287effc3u, 0xac6732c6u, 0x8c4f5573u,
    0x695b27b0u, 0xbbca58c8u, 0xe1ffa35du, 0xb8f011a0u,
    0x10fa3d98u, 0xfd2183b8u, 0x4afcb56cu, 0x2dd1d35bu,
    0x9a53e479u, 0xb6f84565u, 0xd28e49bcu, 0x4bfb9790u,
    0xe1ddf2dau, 0xa4cb7e33u, 0x62fb1341u, 0xcee4c6e8u,
    0xef20cadau, 0x36774c01u, 0xd07e9efeu, 0x2bf11fb4u,
    0x95dbda4du, 0xae909198u, 0xeaad8e71u, 0x6b93d5a0u,
    0xd08ed1d0u, 0xafc725e0u, 0x8e3c5b2fu, 0x8e7594b7u,
    0x8ff6e2fbu, 0xf2122b64u, 0x8888b812u, 0x900df01cu,
    0x4fad5ea0u, 0x688fc31cu, 0xd1cff191u, 0xb3a8c1adu,
    0x2f2f2218u, 0xbe0e1777u, 0xea752dfeu, 0x8b021fa1u,
    0xe5a0cc0fu, 0xb56f74e8u, 0x18acf3d6u, 0xce89e299u,
    0xb4a84fe0u, 0xfd13e0b7u, 0x7cc43b81u, 0xd2ada8d9u,
    0x165fa266u, 0x80957705u, 0x93cc7314u, 0x211a1477u,
    0xe6ad2065u, 0x77b5fa86u, 0xc75442f5u, 0xfb9d35cfu,
    0xebcdaf0cu, 0x7b3e89a0u, 0xd6411bd3u, 0xae1e7e49u,
    0x00250e2du, 0x2071b35eu, 0x226800bbu, 0x57b8e0afu,
    0x2464369bu, 0xf009b91eu, 0x5563911du, 0x59dfa6aau,
    0x78c14389u, 0xd95a537fu, 0x207d5ba2u, 0x02e5b9c5u,
    0x83260376u, 0x6295cfa9u, 0x11c81968u, 0x4e734a41u,
    0xb3472dcau, 0x7b14a94au, 0x1c510dc9u, 0x66559f60u,
    0x444a256du, 0x88862471u, 0x493fa4e4u, 0x30505decu,
    0xec4cebacu, 0x403dc4e8u, 0x5e4ec733u, 0x585e5410u,
    0x241f0878u, 0x42d82954u, 0x5e46b180u, 0x4d25056fu,
    0x97010e0du, 0x4c4ebe6bu, 0x12583f14u, 0x206586b7u,
    0x5c131e24u, 0x6191c2bcu, 0x1c5911f5u, 0xf82520e7u,
    0xdcbbc24au, 0xccb1d81fu, 0x35325c51u, 0x193f31b7u,
    0x05551384u, 0x0d6a01aeu, 0x664333e8u, 0xa65f2086u,
    0x2e600f46u, 0x27747037u, 0x3477b4c4u, 0x50d69fc8u,
    0x5396d24cu, 0xbb3ecad1u, 0x3e2fce94u, 0x2cb61af3u,
    0x6e4c03deu, 0x52ff5633u, 0xb08f7b73u, 0x83d3ac7bu,
    0xad41efb4u, 0x51fcc1beu, 0xe17e0321u, 0x03c578c1u,
    0x97508dfbu, 0xedba3b2bu, 0x4e39ab69u, 0xbf105b77u,
    0xb31815c9u, 0xdd908a79u, 0x7e18d487u, 0x01df6928u,
    0x9b64e0c7u, 0x0d5c13e6u, 0x3f4adfaeu, 0xae54de52u,
    0x710acd1cu, 0x1f8ffb02u, 0xc265e82bu, 0x63f82da2u,
    0x331f27b1u, 0x7e20d0e1u, 0x8e4e85d7u, 0x75d63091u,
    0x67ec8f5fu, 0x97352334u, 0x28cb560fu, 0xec749a11u,
    0x29966a0bu, 0x3629a6a5u, 0xcf1c7cbeu, 0x5145962bu,
    0x1465a3d8u, 0xd6ec48d9u, 0x6bd5c288u, 0x85970f0fu,
    0xaef6f312u, 0x9cd7b583u, 0x8fe9af11u, 0xf33c6aceu,
    0xa22f5863u, 0xc1b340e0u, 0x54bd9090u, 0x069c4d91u,
    0x4c677b15u, 0x05031a07u, 0xe361550au, 0x5802f3b8u,
    0x136c7beau, 0x79e7e5cfu, 0xaddf78b1u, 0xf2edf9f1u,
    0xb85fc17eu, 0x3120f0e0u, 0x3411ed66u, 0xcf93308bu,
    0x064ec4d6u, 0xc3d10ddcu, 0xfab9afc8u, 0xd8cdae40u,
    0x85efb975u, 0xbd4c6c3fu, 0x5b8c75b5u, 0xc5836b2au,
    0x3024dd9bu, 0xf0992a04u, 0xab803a75u, 0x3ad3fa66u,
    0x43033e4fu, 0x28499bc4u, 0x37b0e5aeu, 0x72e2fa48u,
    0x9a1eaf2au, 0x5c59d5b1u, 0x7e3bf828u, 0x87fe1023u,
    0x2b699c6cu, 0xc38f0074u, 0x235812d0u, 0x9c3e8f7fu,
    0x5f64f7fbu, 0xd655c073u, 0x2ccd26f5u, 0xe6ff1faeu,
    0xcae0cfa6u, 0x2266fc0bu, 0xbdf3bc1bu, 0xb0b0bd43u,
    0x8a2979bfu, 0x748c770du, 0x19dc0712u, 0xa60246f4u,
    0x883daae2u, 0x9cbf5a4cu, 0xbb18d146u, 0xf31491ceu,
    0x37926613u, 0xc63f4afeu, 0xf218f31au, 0xbb57b631u,
    0x9087c1f5u, 0x0a6c6b8eu, 0x9da97d42u, 0xa64d9f08u,
    0xdeb2da4du, 0x5cb3b37cu, 0x3520cbdau, 0x2ece19dau,
    0xd81d8f41u, 0xc1c76fa2u, 0x4f608634u, 0x7ced47a8u,
    0x639fbe78u, 0xcf3abc36u, 0x1b29f38bu, 0xe1ae3c3au,
    0xfafccfa5u, 0xcbb036fdu, 0x952db427u, 0xe23a01c5u,
    0xce312073u, 0xd9f6af24u, 0x570471fbu, 0x3ab0dfd7u,
    0xaef0dc97u, 0x6063a310u, 0x4a0ae5c8u, 0xe2cbb5d5u,
    0x5adf393bu, 0x57b7d5f7u, 0xcfed3270u, 0x94b107c7u,
    0x233db142u, 0x3dcc7a63u, 0xc9a37cb2u, 0xd3f069bdu,
    0xfbbadeb6u, 0xf0e03d03u, 0x87855392u, 0x0f594533u,
    0x253873fdu, 0x77b26facu, 0xccb52e6bu, 0x0e2c3c0eu,
    0x2daa3bdfu, 0x6c7e6c76u, 0x40c14e67u, 0xc64b03c7u,
    0xff0350a4u, 0x777fa109u, 0x306e0517u, 0xc2ae016bu,
    0x77c6fe4bu, 0x87f65909u, 0x257672e7u, 0x4f04279eu,
    0xef7a0792u, 0xfd146133u, 0x5c141031u, 0x4a88ebd0u,
    0x27cbeea6u, 0x0ffb424cu, 0x1d1ab1c4u, 0xdc3641feu,
    0xd5967c66u, 0xa6b7e94eu, 0xbe520953u, 0x3f9aed81u,
    0x2a1bf948u, 0x69fb19c6u, 0xbab65d27u, 0xfea09320u,
    0x7997c272u, 0x376a2c6eu, 0x9cab3d1du, 0x445a074au,
    0x625d2919u, 0xf41bedc3u, 0x7ca6ca60u, 0x4b14c8d4u,
    0x38de7621u, 0xc3ba2702u, 0xb228ba30u, 0xec8db3f7u,
    0x25a62ea4u, 0x7bba1379u, 0xf2c03ac7u, 0x8963843fu,
    0xb2abd4b4u, 0xb182caedu, 0x797bf5e4u, 0xc4be1ab5u,
    0xcf0e275eu, 0xda8753fbu, 0xd244e76cu, 0xf59bf739u,
    0x5593aff2u, 0x415f27ffu, 0x208ab08fu, 0x40c15652u,
    0x0c3bca3cu, 0x07a17076u, 0xd81e408fu, 0x2c64e458u,
    0x35596b46u, 0xed4cb19cu, 0x38cba3bau, 0xa2ee0825u,
    0xd5cb88eeu, 0x88933357u, 0xa919df68u, 0x1bbe51cbu,
    0x2c3055e6u, 0xa51d4bb4u, 0x364015b8u, 0xac3d0b39u,
    0x80bd4892u, 0x08183b3eu, 0x66ae8304u, 0x503c1394u,
    0x24c88e91u, 0x87358abdu, 0xacc07863u, 0x2b1ff3a4u,
    0xe6f2c3b2u, 0x5b9f822cu, 0xbb390adcu, 0x5cfbcb6eu,
    0xa4a2a116u, 0x1c5c8cecu, 0x330260cfu, 0xd46bda86u,
    0x2d0e42c4u, 0x0dfb90d9u, 0x5b880d73u, 0x3cbaaa79u,
    0x7110c3c9u, 0x08c8ab87u, 0x239e2eb5u, 0x4f365e2cu,
    0xbaab063cu, 0x32d43fafu, 0xe9ba24afu, 0x697773fdu,
    0x2c9ed0fau, 0xf663c7c2u, 0xbbb29c55u, 0xa2d7e5c2u,
    0x98c2aecbu, 0xd46a01e8u, 0x8bb182dau, 0x38eb4ccau,
    0xd2934e6du, 0x8db0e0c3u, 0x0122fc6bu, 0xb1c2f97bu,
    0xbf5218f1u, 0xa6075681u, 0x0de5ac5au, 0xe45c45fau,
    0xa45004e2u, 0x75676a24u, 0xe06c03dbu, 0xba4e0a47u,
    0x0cfad044u, 0x7b3c16c7u, 0xd42aac5au, 0x341f1138u,
    0x22d73f5au, 0xb6075a4du, 0x7ffeb906u, 0x8a65fbb7u,
    0x8e72485bu, 0xfccac180u, 0x7c95e4bcu, 0xb8f8ccf2u,
    0x4a638ac9u, 0x1c470e05u, 0x9136670au, 0xf6b88f56u,
    0x3d60afc6u, 0x5cc93d6eu, 0xaa2deda5u, 0xaf5fb8c5u,
    0x146bc62cu, 0xc68cfc34u, 0x5ed4f47fu, 0x78aa8cd1u,
    0x0e0bf109u, 0xdb319aaeu, 0x0f39ff19u, 0x3b06f680u,
    0x642cbba5u, 0xcd041f81u, 0x5447a514u, 0x31e20db2u,
    0x0f2991f2u, 0x8d6b60d0u, 0xfc8d6baeu, 0x14b87c26u,
    0x0509e1cbu, 0x22a1fe14u, 0x0d4ab164u, 0xb8d07acbu,
    0x27e0665fu, 0xaa6c6e3bu, 0x3c633466u, 0x5259a648u,
    0xd09b5966u, 0xaca94482u, 0x09c6dc59u, 0xb32e8ba4u,
    0x2f8a3f2fu, 0xc8182a66u, 0x9cfdd6fdu, 0x6142a59bu,
    0x1ef1a403u, 0xaea959f9u, 0xfea5a70eu, 0x82688377u,
    0xdca11279u, 0x893ba7a5u, 0x91a5c9bdu, 0x6e29b9c4u,
    0x9fb19524u, 0x6abb1957u, 0xff53f03cu, 0x1ba5c858u,
    0x48c83aaau, 0xc7b5618du, 0x7c59aab0u, 0x2038d18fu,
    0x00795c0bu, 0x7082e6c6u, 0xb2bedec0u, 0xd67dce02u,
    0xa68466c9u, 0xb28c73afu, 0x3e0b8cfbu, 0x5f350fecu,
    0x5f81272eu, 0x09c351e6u, 0x7aa82d6bu, 0xbf0b2171u,
    0x77a702b9u, 0x87898607u, 0xd96bc275u, 0xa534acf6u,
);

fn blowfish_encrypt(P: ptr<function, array<u32, 18>>, S: ptr<function, array<u32, 1024>>, xl: u32, xr: u32) -> vec2<u32> {
    var l = xl;
    var r = xr;
    for (var i: u32 = 0u; i < 16u; i++) {
        l ^= (*P)[i];
        var val = (*S)[(l >> 24u) & 0xffu];
        val += (*S)[256u + ((l >> 16u) & 0xffu)];
        val ^= (*S)[512u + ((l >> 8u) & 0xffu)];
        val += (*S)[768u + (l & 0xffu)];
        r ^= val;
        let tmp = l; l = r; r = tmp;
    }
    let tmp = l; l = r; r = tmp;
    r ^= (*P)[16u];
    l ^= (*P)[17u];
    return vec2(l, r);
}

fn eksblowfish_setup(password: array<u32, 16>, pw_len: u32, salt: array<u32, 4>, cost: u32) -> (array<u32, 18>, array<u32, 1024>) {
    var P: array<u32, 18> = P_ORIG;
    var S: array<u32, 1024> = S_ORIG;

    // XOR password into P array
    var j: u32 = 0u;
    for (var i: u32 = 0u; i < 18u; i++) {
        var pw_word: u32 = 0u;
        for (var k: u32 = 0u; k < 4u; k++) {
            pw_word |= ((password[j / 4u] >> ((j % 4u) * 8u)) & 0xffu) << (k * 8u);
            j = (j + 1u) % pw_len;
        }
        P[i] ^= pw_word;
    }

    // Salt expansion
    var l: u32 = 0u; var r: u32 = 0u;
    for (var i: u32 = 0u; i < 18u; i += 2u) {
        let enc = blowfish_encrypt(&P, &S, l, r);
        l = enc.x ^ salt[i / 2u % 4u];
        r = enc.y;
        P[i] = l; P[i+1] = r;
    }

    for (var i: u32 = 0u; i < 1024u; i += 2u) {
        let enc = blowfish_encrypt(&P, &S, l, r);
        l = enc.x; r = enc.y;
        S[i] = l; S[i+1] = r;
    }

    // Cost rounds
    let rounds: u32 = 1u << cost;
    for (var rnd: u32 = 0u; rnd < rounds; rnd++) {
        // XOR salt again
        for (var i: u32 = 0u; i < 18u; i += 2u) {
            let enc = blowfish_encrypt(&P, &S, l, r);
            l = enc.x ^ salt[i / 2u % 4u];
            r = enc.y;
            P[i] = l; P[i+1] = r;
        }
        for (var i: u32 = 0u; i < 1024u; i += 2u) {
            let enc = blowfish_encrypt(&P, &S, l, r);
            l = enc.x; r = enc.y;
            S[i] = l; S[i+1] = r;
        }
        // XOR password again
        j = 0u;
        for (var i: u32 = 0u; i < 18u; i += 2u) {
            var pw_word1: u32 = 0u; var pw_word2: u32 = 0u;
            for (var k: u32 = 0u; k < 4u; k++) {
                pw_word1 |= ((password[j / 4u] >> ((j % 4u) * 8u)) & 0xffu) << (k * 8u);
                j = (j + 1u) % pw_len;
            }
            for (var k: u32 = 0u; k < 4u; k++) {
                pw_word2 |= ((password[j / 4u] >> ((j % 4u) * 8u)) & 0xffu) << (k * 8u);
                j = (j + 1u) % pw_len;
            }
            let enc = blowfish_encrypt(&P, &S, l ^ pw_word1, r ^ pw_word2);
            l = enc.x; r = enc.y;
            P[i] = l; P[i+1] = r;
        }
        for (var i: u32 = 0u; i < 1024u; i += 2u) {
            let enc = blowfish_encrypt(&P, &S, l, r);
            l = enc.x; r = enc.y;
            S[i] = l; S[i+1] = r;
        }
    }

    return (P, S);
}

@compute @workgroup_size(4)  // bcrypt is heavy — small workgroups
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if idx >= count { return; }
    let cand = candidates[idx];
    let (P, S) = eksblowfish_setup(cand.password, cand.len, config.salt, config.cost);
    // For bcrypt, final result is "OrpheanBeholderScryDoubt" encrypted with Blowfish
    var l: u32 = 0x4f727068u; // "Orph"
    var r: u32 = 0x65616e42u; // "eanB"
    let enc1 = blowfish_encrypt(&P, &S, l, r);
    l = 0x65686f6cu; // "ehol"
    r = 0x64657253u; // "derS"
    let enc2 = blowfish_encrypt(&P, &S, l, r);
    l = 0x63727944u; // "cryD"
    r = 0x6f756274u; // "oubt"
    let enc3 = blowfish_encrypt(&P, &S, l, r);

    let ok = enc1.x == target[0] && enc1.y == target[1] &&
             enc2.x == target[2] && enc2.y == target[3] &&
             enc3.x == target[4] && enc3.y == target[5];
    if ok { results[idx] = HashResult(1u, idx, vec4(0u)); }
    else { results[idx] = HashResult(0u, idx, vec4(0u)); }
}
