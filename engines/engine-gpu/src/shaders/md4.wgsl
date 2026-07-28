// MD4 compute shader — used for NTLM (with UTF16-LE encoding of password)
struct Candidate { data: array<u32, 16> }
struct HashResult { matched: u32 }

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<HashResult>;
@group(0) @binding(2) var<storage, read> target: array<u32, 16>;
@group(0) @binding(3) var<uniform> count: u32;

fn rol(x: u32, n: u32) -> u32 { return (x << n) | (x >> (32u - n)); }

fn f(x: u32, y: u32, z: u32) -> u32 { return (x & y) | (~x & z); }
fn g(x: u32, y: u32, z: u32) -> u32 { return (x & y) | (x & z) | (y & z); }
fn h(x: u32, y: u32, z: u32) -> u32 { return x ^ y ^ z; }

fn utf16le_encode(password: array<u8, 64>, len: u32) -> (array<u32, 16>, u32) {
  var out: array<u32, 16>;
  for (var i: u32 = 0u; i < 16u; i++) { out[i] = 0u; }
  var byte_count: u32 = 0u;
  for (var i: u32 = 0u; i < len; i++) {
    let c = password[i];
    let byte_idx = byte_count % 4u;
    let word_idx = byte_count / 4u;
    out[word_idx] |= u32(c) << (byte_idx * 8u);
    byte_count += 2u; // each UTF16 char = 2 bytes (ASCII extended)
  }
  return (out, byte_count);
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  if (gid.x >= count) { return; }

  var password_bytes: array<u8, 64>;
  for (var i: u32 = 0u; i < 64u; i++) {
    password_bytes[i] = candidates[gid.x].data[i / 4u] >> ((i % 4u) * 8u);
  }
  var pwlen: u32 = 0u;
  for (var i: u32 = 0u; i < 64u; i++) { if (password_bytes[i] == 0u) { pwlen = i; break; } }
  if (pwlen == 0u && password_bytes[0] != 0u) { pwlen = 64u; }

  let (w_enc, byte_count) = utf16le_encode(password_bytes, pwlen);

  var w: array<u32, 16>;
  for (var i: u32 = 0u; i < 16u; i++) { w[i] = w_enc[i]; }
  w[byte_count / 4u] |= 0x80u << ((byte_count % 4u) * 8u);
  w[14] = byte_count * 8u;

  var hh: array<u32, 4> = array(0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u);
  var a = hh[0]; var b = hh[1]; var c = hh[2]; var d = hh[3];
  var temp: u32;

  // Round 1
  for (var i: u32 = 0u; i < 16u; i++) {
    let k = i;
    temp = rol(a + f(b, c, d) + w[k], 3u);
    a = d; d = c; c = b; b = temp;
  }
  // Round 2
  for (var i: u32 = 0u; i < 16u; i++) {
    let k = (i % 4u) * 4u + i / 4u;
    let s = (i % 4u) * 4u + 3u;
    temp = rol(a + g(b, c, d) + w[k] + 0x5A827999u, s);
    a = d; d = c; c = b; b = temp;
  }
  // Round 3
  for (var i: u32 = 0u; i < 16u; i++) {
    let k = array(0u, 8u, 4u, 12u, 2u, 10u, 6u, 14u, 1u, 9u, 5u, 13u, 3u, 11u, 7u, 15u)[i];
    let s = array(3u, 5u, 9u, 13u)[i % 4u];
    temp = rol(a + h(b, c, d) + w[k] + 0x6ED9EBA1u, s);
    a = d; d = c; c = b; b = temp;
  }

  hh[0] += a; hh[1] += b; hh[2] += c; hh[3] += d;
  let matched = (hh[0] == target[0] && hh[1] == target[1] && hh[2] == target[2] && hh[3] == target[3]);
  results[gid.x].matched = select(0u, 1u, matched);
}
