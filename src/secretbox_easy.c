static const u8 sigma[16] = "expand 32-byte k";

static int crypto_stream_salsa20_xor_skip(u8 *c, const u8 *m, u64 b, const u8 *n, const u8 *k, u64 skip)
{
  u8 z[16], x[64];
  u64 u, i;
  if (!b) return 0;
  FOR(i, 16) z[i] = 0;
  FOR(i, 8) z[i] = n[i];
  while (skip >= 64) {
    u = 1;
    for (i = 8; i < 16; ++i) {
      u += (u64) z[i];
      z[i] = u;
      u >>= 8;
    }
    skip -= 64;
  }
  if (skip) {
    crypto_core_salsa20(x, z, k, sigma);
    i = 0;
    while (i < 64 - skip && i < b) {
      c[i] = (m ? m[i] : 0) ^ x[i + skip];
      ++i;
    }
    b -= i;
    c += i;
    if (m) m += i;
    u = 1;
    for (i = 8; i < 16; ++i) {
      u += (u64) z[i];
      z[i] = u;
      u >>= 8;
    }
  }
  while (b >= 64) {
    crypto_core_salsa20(x, z, k, sigma);
    FOR(i, 64) c[i] = (m ? m[i] : 0) ^ x[i];
    u = 1;
    for (i = 8; i < 16; ++i) {
      u += (u64) z[i];
      z[i] = u;
      u >>= 8;
    }
    b -= 64;
    c += 64;
    if (m) m += 64;
  }
  if (b) {
    crypto_core_salsa20(x, z, k, sigma);
    FOR(i, b) c[i] = (m ? m[i] : 0) ^ x[i];
  }
  return 0;
}

static int crypto_secretbox_easy(u8 *c, const u8 *m, u64 d, const u8 *n, const u8 *k)
{
  u8 s[32], x[32];
  crypto_core_hsalsa20(s, n, k, sigma);
  crypto_stream_salsa20(x, 32, n + 16, s);
  crypto_stream_salsa20_xor_skip(c + 16, m, d, n + 16, s, 32);
  crypto_onetimeauth_poly1305(c, c + 16, d, x);
  return 0;
}

static int crypto_secretbox_easy_open(u8 *m, const u8 *c, u64 d, const u8 *n, const u8 *k)
{
  u8 s[32], x[32];
  int v;
  if (d < 16) return -1;
  crypto_core_hsalsa20(s, n, k, sigma);
  crypto_stream_salsa20(x, 32, n + 16, s);
  v = crypto_onetimeauth_poly1305_verify(c, c + 16, d - 16, x);
  if (v == 0) {
    crypto_stream_salsa20_xor_skip(m, c + 16, d - 16, n + 16, s, 32);
    return 0;
  }
  return -1;
}
