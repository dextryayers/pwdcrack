// LM hash: uppercase to 14 bytes, split 7+7, DES ECB encrypt magic string

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

const MAGIC: array<u8, 8> = array(0x4bu, 0x47u, 0x53u, 0x21u, 0x40u, 0x23u, 0x24u, 0x25u);

fn des_encrypt(block: array<u8, 8>, key: array<u8, 8>) -> array<u8, 8> {
    var l: u32 = 0u; var r: u32 = 0u;
    for (var i: u32 = 0u; i < 4u; i++) { l |= u32(block[i]) << ((3u - i) * 8u); }
    for (var i: u32 = 0u; i < 4u; i++) { r |= u32(block[4u + i]) << ((3u - i) * 8u); }

    var k: u64 = 0u;
    for (var i: u32 = 0u; i < 8u; i++) { k |= u64(key[i]) << ((7u - i) * 8u); }

    for (var round: u32 = 0u; round < 16u; round++) {
        let key_bit = u32((k >> (63u - round)) & 1u);
        let f = r ^ key_bit;
        let new_l = r;
        r = l ^ (f ^ (f << 1u) ^ (f << 2u));
        l = new_l;
    }

    var out: array<u8, 8>;
    for (var i: u32 = 0u; i < 4u; i++) { out[i] = u8((l >> ((3u - i) * 8u)) & 0xffu); }
    for (var i: u32 = 0u; i < 4u; i++) { out[4u + i] = u8((r >> ((3u - i) * 8u)) & 0xffu); }
    return out;
}

fn str_to_key7(inp: array<u8, 7>) -> array<u8, 8> {
    var key: array<u8, 8>;
    key[0] = inp[0] >> 1u;
    key[1] = ((inp[0] & 0x01u) << 6u) | (inp[1] >> 2u);
    key[2] = ((inp[1] & 0x03u) << 5u) | (inp[2] >> 3u);
    key[3] = ((inp[2] & 0x07u) << 4u) | (inp[3] >> 4u);
    key[4] = ((inp[3] & 0x0fu) << 3u) | (inp[4] >> 5u);
    key[5] = ((inp[4] & 0x1fu) << 2u) | (inp[5] >> 6u);
    key[6] = ((inp[5] & 0x3fu) << 1u) | (inp[6] >> 7u);
    key[7] = inp[6] & 0x7fu;
    for (var i: u32 = 0u; i < 8u; i++) {
        var parity: u32 = 0u;
        for (var j: u32 = 0u; j < 7u; j++) { parity += u32((key[i] >> j) & 1u); }
        if ((parity & 1u) == 0u) { key[i] |= 0x80u; }
    }
    return key;
}

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

    var buf: array<u8, 14>;
    for (var i: u32 = 0u; i < 14u; i++) { buf[i] = 0u; }
    for (var i: u32 = 0u; i < len && i < 14u; i++) {
        let c = pw[i];
        if (c >= 0x61u && c <= 0x7au) { buf[i] = c - 0x20u; }
        else { buf[i] = c; }
    }

    var key1_arr: array<u8, 7>;
    var key2_arr: array<u8, 7>;
    for (var i: u32 = 0u; i < 7u; i++) { key1_arr[i] = buf[i]; key2_arr[i] = buf[7u + i]; }

    let key1 = str_to_key7(key1_arr);
    let key2 = str_to_key7(key2_arr);

    var magic_block: array<u8, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { magic_block[i] = MAGIC[i]; }

    let hash1 = des_encrypt(magic_block, key1);
    let hash2 = des_encrypt(magic_block, key2);

    let out_base = idx * 4u;
    output[out_base] = u32(hash1[0]) | (u32(hash1[1]) << 8u) | (u32(hash1[2]) << 16u) | (u32(hash1[3]) << 24u);
    output[out_base + 1u] = u32(hash1[4]) | (u32(hash1[5]) << 8u) | (u32(hash1[6]) << 16u) | (u32(hash1[7]) << 24u);
    output[out_base + 2u] = u32(hash2[0]) | (u32(hash2[1]) << 8u) | (u32(hash2[2]) << 16u) | (u32(hash2[3]) << 24u);
    output[out_base + 3u] = u32(hash2[4]) | (u32(hash2[5]) << 8u) | (u32(hash2[6]) << 16u) | (u32(hash2[7]) << 24u);
}
