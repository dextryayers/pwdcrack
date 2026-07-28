// MD2 hash — 128-bit output, 16-byte block, S-box substitution

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

const S: array<u8, 256> = array(
    41u, 46u, 67u, 201u, 162u, 216u, 124u, 1u, 61u, 54u, 84u, 161u, 236u, 240u, 6u, 19u,
    98u, 167u, 5u, 243u, 192u, 199u, 115u, 140u, 152u, 147u, 43u, 217u, 188u, 76u, 130u, 202u,
    30u, 155u, 87u, 60u, 253u, 212u, 224u, 22u, 103u, 66u, 111u, 24u, 138u, 23u, 229u, 18u,
    190u, 78u, 196u, 214u, 218u, 158u, 222u, 73u, 160u, 251u, 245u, 142u, 187u, 47u, 238u, 122u,
    169u, 104u, 121u, 145u, 21u, 178u, 7u, 63u, 148u, 194u, 16u, 137u, 11u, 34u, 95u, 33u,
    128u, 127u, 93u, 154u, 90u, 144u, 50u, 39u, 53u, 62u, 204u, 231u, 191u, 247u, 151u, 3u,
    255u, 25u, 48u, 179u, 72u, 165u, 181u, 209u, 215u, 94u, 146u, 42u, 172u, 86u, 170u, 198u,
    79u, 184u, 56u, 210u, 150u, 164u, 125u, 182u, 118u, 252u, 107u, 226u, 156u, 116u, 4u, 241u,
    69u, 157u, 112u, 89u, 100u, 113u, 135u, 32u, 134u, 91u, 207u, 101u, 230u, 45u, 168u, 2u,
    27u, 96u, 37u, 173u, 174u, 176u, 185u, 246u, 28u, 70u, 97u, 105u, 52u, 64u, 126u, 15u,
    85u, 71u, 163u, 35u, 221u, 81u, 175u, 58u, 195u, 92u, 249u, 206u, 186u, 197u, 234u, 38u,
    44u, 83u, 13u, 110u, 133u, 40u, 132u, 9u, 211u, 223u, 205u, 244u, 65u, 129u, 77u, 82u,
    106u, 220u, 55u, 200u, 108u, 193u, 171u, 250u, 36u, 225u, 123u, 8u, 12u, 189u, 177u, 74u,
    120u, 136u, 149u, 139u, 227u, 99u, 232u, 109u, 233u, 203u, 213u, 254u, 59u, 0u, 29u, 57u,
    242u, 239u, 183u, 14u, 102u, 88u, 208u, 228u, 166u, 119u, 114u, 248u, 235u, 117u, 75u, 10u,
    49u, 68u, 80u, 180u, 143u, 237u, 31u, 26u, 219u, 153u, 141u, 51u, 159u, 17u, 131u, 20u,
);

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if (idx >= config.pcount) { return; }

    var pw: array<u8, 64>;
    let base = idx * 16u;
    for (var i: u32 = 0u; i < 64u; i++) {
        pw[i] = u8((input[base + i / 4u] >> ((i % 4u) * 8u)) & 0xffu);
    }
    var len: u32 = 0u;
    for (var i: u32 = 0u; i < 64u; i++) { if (pw[i] == 0u) { len = i; break; } }
    if (len == 0u && pw[0] != 0u) { len = 64u; }

    var pad_len = len;
    let need = 16u - (len % 16u);
    var total = len + need;
    var buf: array<u8, 256>;
    for (var i: u32 = 0u; i < len; i++) { buf[i] = pw[i]; }
    for (var i: u32 = 0u; i < need; i++) { buf[len + i] = u8(need); }

    var checksum: array<u8, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { checksum[i] = 0u; }
    var last: u8 = 0u;
    for (var i: u32 = 0u; i < total; i += 16u) {
        for (var j: u32 = 0u; j < 16u; j++) {
            let idx2 = i + j;
            let c = buf[idx2];
            checksum[j] ^= S[u32(c ^ last)];
            last = checksum[j];
        }
    }
    for (var i: u32 = 0u; i < 16u; i++) { buf[total + i] = checksum[i]; }
    total += 16u;

    var x: array<u8, 48>;
    for (var i: u32 = 0u; i < 48u; i++) { x[i] = 0u; }
    for (var i: u32 = 0u; i < total; i += 16u) {
        for (var j: u32 = 0u; j < 16u; j++) {
            x[16u + j] = buf[i + j];
            x[32u + j] = x[16u + j] ^ x[j];
        }
        var t: u8 = 0u;
        for (var j: u32 = 0u; j < 18u; j++) {
            for (var k: u32 = 0u; k < 48u; k++) {
                t = x[k] ^ S[u32(t)];
                x[k] = t;
            }
            t = t + u8(j);
        }
    }

    let out_base = idx * 4u;
    for (var i: u32 = 0u; i < 4u; i++) {
        output[out_base + i] = u32(x[i * 4u]) | (u32(x[i * 4u + 1u]) << 8u) |
                               (u32(x[i * 4u + 2u]) << 16u) | (u32(x[i * 4u + 3u]) << 24u);
    }
}
