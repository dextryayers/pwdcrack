// BLAKE2b-256 compute shader
struct Candidate { data: array<u32, 16> }
struct HashResult { matched: u32 }

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<HashResult>;
@group(0) @binding(2) var<storage, read> target: array<u32, 16>;
@group(0) @binding(3) var<uniform> count: u32;

const IV: array<u64, 8> = array(
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
);

const SIGMA: array<u32, 96> = array(
  0u,1u,2u,3u,4u,5u,6u,7u,8u,9u,10u,11u,12u,13u,14u,15u,
  14u,10u,4u,8u,9u,15u,13u,6u,1u,12u,0u,2u,11u,7u,5u,3u,
  11u,8u,12u,0u,5u,2u,15u,13u,10u,14u,3u,6u,7u,1u,9u,4u,
  7u,9u,3u,1u,13u,12u,11u,14u,2u,6u,5u,10u,4u,0u,15u,8u,
  9u,0u,5u,7u,2u,4u,10u,15u,14u,1u,11u,12u,6u,8u,3u,13u,
  2u,12u,6u,10u,0u,11u,8u,3u,4u,13u,7u,5u,15u,14u,1u,9u,
);

fn rotr64(x: u64, r: u32) -> u64 { return (x >> r) | (x << (64u - r)); }

fn g(v: ptr<function, array<u64, 16>>, a: u32, b: u32, c: u32, d: u32, x: u64, y: u64) {
  (*v)[a] = (*v)[a] + (*v)[b] + x;
  (*v)[d] = rotr64((*v)[d] ^ (*v)[a], 32u);
  (*v)[c] = (*v)[c] + (*v)[d];
  (*v)[b] = rotr64((*v)[b] ^ (*v)[c], 24u);
  (*v)[a] = (*v)[a] + (*v)[b] + y;
  (*v)[d] = rotr64((*v)[d] ^ (*v)[a], 16u);
  (*v)[c] = (*v)[c] + (*v)[d];
  (*v)[b] = rotr64((*v)[b] ^ (*v)[c], 63u);
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  if (gid.x >= count) { return; }
  var password_bytes: array<u8, 128>;
  for (var i: u32 = 0u; i < 128u; i++) {
    password_bytes[i] = candidates[gid.x].data[i / 4u] >> ((i % 4u) * 8u);
  }
  var len: u32 = 0u;
  for (var i: u32 = 0u; i < 128u; i++) { if (password_bytes[i] == 0u) { len = i; break; } }
  if (len == 0u && password_bytes[0] != 0u) { len = 128u; }

  var h: array<u64, 8>;
  for (var i: u32 = 0u; i < 8u; i++) { h[i] = IV[i]; }
  h[0] ^= 0x01010000u64 ^ (32u64 << 32u);

  var m: array<u64, 16>;
  for (var i: u32 = 0u; i < 16u; i++) { m[i] = 0u; }
  for (var i: u32 = 0u; i < len; i++) {
    let word_idx = i / 8u;
    let byte_idx = i % 8u;
    m[word_idx] |= u64(password_bytes[i]) << (byte_idx * 8u);
  }

  var v: array<u64, 16>;
  for (var i: u32 = 0u; i < 8u; i++) { v[i] = h[i]; }
  for (var i: u32 = 0u; i < 8u; i++) { v[i + 8u] = IV[i]; }
  v[12] ^= u64(len);

  for (var r: u32 = 0u; r < 12u; r++) {
    let s = r * 16u;
    g(&v, 0u, 4u, 8u, 12u, m[SIGMA[s + 0u]], m[SIGMA[s + 1u]]);
    g(&v, 1u, 5u, 9u, 13u, m[SIGMA[s + 2u]], m[SIGMA[s + 3u]]);
    g(&v, 2u, 6u, 10u, 14u, m[SIGMA[s + 4u]], m[SIGMA[s + 5u]]);
    g(&v, 3u, 7u, 11u, 15u, m[SIGMA[s + 6u]], m[SIGMA[s + 7u]]);
    g(&v, 0u, 5u, 10u, 15u, m[SIGMA[s + 8u]], m[SIGMA[s + 9u]]);
    g(&v, 1u, 6u, 11u, 12u, m[SIGMA[s + 10u]], m[SIGMA[s + 11u]]);
    g(&v, 2u, 7u, 8u, 13u, m[SIGMA[s + 12u]], m[SIGMA[s + 13u]]);
    g(&v, 3u, 4u, 9u, 14u, m[SIGMA[s + 14u]], m[SIGMA[s + 15u]]);
  }

  for (var i: u32 = 0u; i < 8u; i++) { h[i] ^= v[i] ^ v[i + 8u]; }

  let matched = (u32(h[0]) == target[0] && u32(h[0] >> 32u) == target[1] &&
                 u32(h[1]) == target[2] && u32(h[1] >> 32u) == target[3]);
  results[gid.x].matched = select(0u, 1u, matched);
}
