// RIPEMD-160 compute shader
struct Candidate { data: array<u32, 16> }
struct HashResult { matched: u32 }

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<HashResult>;
@group(0) @binding(2) var<storage, read> target: array<u32, 16>;
@group(0) @binding(3) var<uniform> count: u32;

fn rol(x: u32, n: u32) -> u32 { return (x << n) | (x >> (32u - n)); }

fn ripemd160_f(j: u32, x: u32, y: u32, z: u32) -> u32 {
  if (j < 16u) { return x ^ y ^ z; }
  else if (j < 32u) { return (x & y) | (~x & z); }
  else if (j < 48u) { return (x | ~y) ^ z; }
  else if (j < 64u) { return (x & z) | (y & ~z); }
  else { return x ^ (y | ~z); }
}

fn ripemd160_f2(j: u32, x: u32, y: u32, z: u32) -> u32 {
  if (j < 16u) { return x ^ y ^ z; }
  else if (j < 32u) { return (x & z) | (y & ~z); }
  else if (j < 48u) { return (x | ~y) ^ z; }
  else if (j < 64u) { return (x & y) | (~x & z); }
  else { return x ^ (y | ~z); }
}

const R: array<u32, 80> = array(
  0u,1u,2u,3u,4u,5u,6u,7u,8u,9u,10u,11u,12u,13u,14u,15u,
  7u,4u,13u,1u,10u,6u,15u,3u,12u,0u,9u,5u,2u,14u,11u,8u,
  3u,10u,14u,4u,9u,15u,8u,1u,2u,7u,0u,6u,13u,11u,5u,12u,
  1u,9u,11u,10u,0u,8u,12u,4u,13u,3u,7u,15u,14u,5u,6u,2u,
  4u,0u,5u,9u,7u,12u,2u,10u,14u,1u,3u,8u,11u,6u,15u,13u,
);
const R2: array<u32, 80> = array(
  5u,14u,7u,0u,9u,2u,11u,4u,13u,6u,15u,8u,1u,10u,3u,12u,
  6u,11u,3u,7u,0u,13u,5u,10u,14u,15u,8u,12u,4u,9u,1u,2u,
  15u,5u,1u,3u,7u,14u,6u,9u,11u,8u,12u,2u,10u,0u,4u,13u,
  8u,6u,4u,1u,3u,11u,15u,0u,5u,12u,2u,13u,9u,7u,10u,14u,
  12u,15u,10u,4u,1u,5u,8u,7u,6u,2u,13u,14u,0u,3u,9u,11u,
);
const S: array<u32, 80> = array(
  11u,14u,15u,12u,5u,8u,7u,9u,11u,13u,14u,15u,6u,7u,9u,8u,
  7u,6u,8u,13u,11u,9u,7u,15u,7u,12u,15u,9u,11u,7u,13u,12u,
  11u,13u,6u,7u,14u,9u,13u,15u,14u,8u,13u,6u,5u,12u,7u,5u,
  11u,12u,14u,15u,14u,15u,9u,8u,9u,14u,5u,6u,8u,6u,5u,12u,
  9u,15u,5u,11u,6u,8u,13u,12u,5u,12u,13u,14u,11u,8u,5u,6u,
);
const S2: array<u32, 80> = array(
  8u,9u,9u,11u,13u,15u,15u,5u,7u,7u,8u,11u,14u,14u,12u,6u,
  9u,13u,15u,7u,12u,8u,9u,11u,7u,7u,12u,7u,6u,15u,13u,11u,
  9u,7u,15u,11u,8u,6u,6u,14u,12u,13u,5u,14u,13u,13u,7u,5u,
  15u,5u,8u,11u,14u,14u,6u,14u,6u,9u,12u,9u,12u,5u,15u,8u,
  8u,5u,12u,9u,12u,5u,14u,6u,8u,13u,6u,5u,15u,13u,11u,11u,
);

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  if (gid.x >= count) { return; }
  var password_bytes: array<u8, 64>;
  for (var i: u32 = 0u; i < 64u; i++) {
    password_bytes[i] = candidates[gid.x].data[i / 4u] >> ((i % 4u) * 8u);
  }
  var len: u32 = 0u;
  for (var i: u32 = 0u; i < 64u; i++) { if (password_bytes[i] == 0u) { len = i; break; } }
  if (len == 0u && password_bytes[0] != 0u) { len = 64u; }

  var w: array<u32, 16>;
  for (var i: u32 = 0u; i < 16u; i++) { w[i] = 0u; }
  for (var i: u32 = 0u; i < len; i++) {
    let word_idx = i / 4u;
    let byte_idx = i % 4u;
    w[word_idx] |= u32(password_bytes[i]) << (byte_idx * 8u);
  }
  w[len / 4u] |= 0x80u << ((len % 4u) * 8u);
  w[14] = len * 8u;

  var h: array<u32, 5> = array(0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u);
  var h2: array<u32, 5> = h;

  var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]; var e = h[4];
  var a2 = h2[0]; var b2 = h2[1]; var c2 = h2[2]; var d2 = h2[3]; var e2 = h2[4];

  for (var j: u32 = 0u; j < 80u; j++) {
    let t = a + ripemd160_f(j, b, c, d) + w[R[j] & 15u] + select(0x00000000u, 0x5A827999u, j < 16u) +
            select(0x6ED9EBA1u, 0x8F1BBCDCu, j < 48u) + select(0xA953FD4Eu, 0x50A28BE6u, j < 64u);
    a = d; d = c; c = rol(b, 10u); b = a; a = a + rol(t, S[j]);
  }
  for (var j: u32 = 0u; j < 80u; j++) {
    let t2 = a2 + ripemd160_f2(j, b2, c2, d2) + w[R2[j] & 15u] + select(0x50A28BE6u, 0x5C4DD124u, j < 16u) +
             select(0x6D703EF3u, 0x7A6D76E9u, j < 48u) + select(0x00000000u, 0x5A827999u, j < 64u);
    a2 = d2; d2 = c2; c2 = rol(b2, 10u); b2 = a2; a2 = a2 + rol(t2, S2[j]);
  }

  h[1] = h[1] + c + d2; h[2] = h[2] + d + e2; h[3] = h[3] + e + a2;
  h[0] = h[0] + a + b2; h[4] = h[4] + b + c2;

  let matched = (h[0] == target[0] && h[1] == target[1] && h[2] == target[2] && h[3] == target[3] && h[4] == target[4]);
  results[gid.x].matched = select(0u, 1u, matched);
}
