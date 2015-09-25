#include <lua.h>
#include "tweetnacl.h"

typedef unsigned char u8;
typedef char i8;
typedef unsigned long long u64;
typedef long long i64;

extern void randombytes(u8*, u64);

#define FOR(i, n) for (i = 0; i < n; ++i)

static u8 *lua_fixedlstring(lua_State *L, int index, int len, i8 *error)
{
  if (!lua_isstring(L, index) || lua_rawlen(L, index) != len)
  {
    lua_pushfstring(L, error, len);
    lua_error(L);
  }
  return (u8*)lua_tostring(L, index);
}

static u8 *lua_minlstring(lua_State *L, int index, int len, u64 *l, i8 *error)
{
  u8 *res;
  size_t slen;
  if (!lua_isstring(L, index) || lua_rawlen(L, index) < len)
  {
    lua_pushfstring(L, error, len);
    lua_error(L);
  }
  res = (u8*)lua_tolstring(L, index, &slen);
  *l = slen;
  return res;
}

static u8 *alloc_str(lua_State *L, u64 l)
{
  void *ud;
  lua_Alloc a = lua_getallocf(L, &ud);
  u8 *s = a(ud, 0, 0, (size_t)l);
  return s;
}

static void free_str(lua_State *L, u8 *s, u64 l)
{
  void *ud;
  lua_Alloc a = lua_getallocf(L, &ud);
  a(ud, s, (size_t)l, 0);
}

static int lua_crypto_randombytes(lua_State *L)
{
  u8 *x;
  u64 xlen;
  double n;
  int isnum;
  n = lua_tonumberx(L, 1, &isnum);
  if (isnum && n >= 0) {
    xlen = n;
    x = alloc_str(L, xlen);
    if (x) {
      randombytes(x, xlen);
      lua_pushlstring(L, (char *)x, xlen);
      free_str(L, x, xlen);
      return 1;
    }
  }
  return 0;
}

static int lua_crypto_verify_16(lua_State *L)
{
  u8 *a, *b;
  a = lua_fixedlstring(L, 1, 16, "Both strings must be %d bytes.");
  b = lua_fixedlstring(L, 2, 16, "Both strings must be %d bytes.");
  lua_pushboolean(L, crypto_verify_16(a, b) + 1);
  return 1;
}

static int lua_crypto_verify_32(lua_State *L)
{
  u8 *a, *b;
  a = lua_fixedlstring(L, 1, 32, "Both strings must be %d bytes.");
  b = lua_fixedlstring(L, 2, 32, "Both strings must be %d bytes.");
  lua_pushboolean(L, crypto_verify_32(a, b) + 1);
  return 1;
}

#include "secretbox_easy.c"

#define crypto_secretbox_PREFIXBYTES (crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES)

static int lua_crypto_secretbox(lua_State *L)
{
  u8 *c, *m, *n, *k;
  u64 d;
  m = lua_minlstring(L, 1, 0, &d, "Message must be a String.");
  n = lua_fixedlstring(L, 2, crypto_secretbox_NONCEBYTES, "Nonce must be %d bytes.");
  k = lua_fixedlstring(L, 3, crypto_secretbox_KEYBYTES, "Key must be %d bytes.");
  c = alloc_str(L, d + crypto_secretbox_PREFIXBYTES);
  if (!c) return 0;
  crypto_secretbox_easy(c, m, d, n, k);
  lua_pushlstring(L, (i8*)c, d + crypto_secretbox_PREFIXBYTES);
  free_str(L, c, d + crypto_secretbox_PREFIXBYTES);
  return 1;
}

static int lua_crypto_secretbox_open(lua_State *L)
{
  u8 *c, *m, *n, *k;
  u64 d;
  c = lua_minlstring(L, 1, crypto_secretbox_PREFIXBYTES, &d, "Secretbox must be at least %d bytes..");
  n = lua_fixedlstring(L, 2, crypto_secretbox_NONCEBYTES, "Nonce must be %d bytes.");
  k = lua_fixedlstring(L, 3, crypto_secretbox_KEYBYTES, "Key must be %d bytes.");
  m = alloc_str(L, d - crypto_secretbox_PREFIXBYTES);
  if (!m) return 0;
  if (crypto_secretbox_easy_open(m, c, d, n, k) != 0)
    lua_pushnil(L);
  else
    lua_pushlstring(L, (i8*)m, d - crypto_secretbox_PREFIXBYTES);
  free_str(L, m, d - crypto_secretbox_PREFIXBYTES);
  return 1;
}

static int lua_crypto_scalarmult(lua_State *L)
{
  u8 *n, *p, q[crypto_scalarmult_BYTES];
  n = lua_fixedlstring(L, 1, crypto_scalarmult_SCALARBYTES, "Scalar n must be %d bytes.");
  p = lua_fixedlstring(L, 2, crypto_scalarmult_BYTES, "Group element p must be %d bytes.");
  crypto_scalarmult(q, n, p);
  lua_pushlstring(L, (i8*)q, crypto_scalarmult_BYTES);
  return 1;
}

static int lua_crypto_scalarmult_base(lua_State *L)
{
  u8 *n, q[crypto_scalarmult_BYTES];
  n = lua_fixedlstring(L, 1, crypto_scalarmult_SCALARBYTES, "Scalar n must be %d bytes.");
  crypto_scalarmult_base(q, n);
  lua_pushlstring(L, (i8*)q, crypto_scalarmult_BYTES);
  return 1;
}

static int lua_crypto_box_keypair(lua_State *L)
{
  u8 pk[crypto_box_PUBLICKEYBYTES], sk[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(pk, sk);
  lua_pushlstring(L, (i8*)pk, crypto_box_PUBLICKEYBYTES);
  lua_pushlstring(L, (i8*)sk, crypto_box_SECRETKEYBYTES);
  return 2;
}

static int lua_crypto_box_beforenm(lua_State *L)
{
  u8 *pk, *sk, shared[crypto_box_BEFORENMBYTES];
  pk = lua_fixedlstring(L, 1, crypto_box_PUBLICKEYBYTES, "Public key must be %d bytes.");
  sk = lua_fixedlstring(L, 2, crypto_box_SECRETKEYBYTES, "Secret key must be %d bytes.");
  crypto_box_beforenm(shared, pk, sk);
  lua_pushlstring(L, (i8*)shared, crypto_box_BEFORENMBYTES);
  return 1;
}

static int lua_crypto_box(lua_State *L)
{
  lua_settop(L, 4);
  lua_pushcfunction(L, lua_crypto_box_beforenm);
  lua_insert(L, 3);
  lua_call(L, 2, 1);
  return lua_crypto_secretbox(L);
}

static int lua_crypto_box_open(lua_State *L)
{
  lua_settop(L, 4);
  lua_pushcfunction(L, lua_crypto_box_beforenm);
  lua_insert(L, 3);
  lua_call(L, 2, 1);
  return lua_crypto_secretbox_open(L);
}

static int lua_crypto_sign_keypair(lua_State *L)
{
  u8 pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
  crypto_sign_keypair(pk, sk);
  lua_pushlstring(L, (i8*)pk, crypto_sign_PUBLICKEYBYTES);
  lua_pushlstring(L, (i8*)sk, crypto_sign_SECRETKEYBYTES);
  return 2;
}

static int lua_crypto_sign(lua_State *L)
{
  u8 *sm, *m, *sk;
  u64 smlen, mlen;
  m = lua_minlstring(L, 1, 0, &mlen, "Message must be a string.");
  sk = lua_fixedlstring(L, 2, crypto_sign_SECRETKEYBYTES, "Secret key must be %d bytes.");
  sm = alloc_str(L, mlen + crypto_sign_BYTES);
  if (!sm) return 0;
  crypto_sign(sm, &smlen, m, mlen, sk);
  lua_pushlstring(L, (i8*)sm, smlen);
  free_str(L, sm, mlen + crypto_sign_BYTES);
  return 1;
}

static int lua_crypto_sign_open(lua_State *L)
{
  u8 *sm, *m, *pk;
  u64 smlen, mlen;
  sm = lua_minlstring(L, 1, crypto_sign_BYTES, &smlen, "Signed message must be at least %d bytes.");
  pk = lua_fixedlstring(L, 2, crypto_sign_PUBLICKEYBYTES, "Public key must be %d bytes.");
  m = alloc_str(L, smlen);
  if (!m) return 0;
  if (crypto_sign_open(m, &mlen, sm, smlen, pk) == -1)
    lua_pushnil(L);
  else
    lua_pushlstring(L, (i8*)m, mlen);
  free_str(L, m, smlen);
  return 1;
}

static int lua_crypto_stream(lua_State *L)
{
  u8 *c, *n, *k;
  u64 d;
  double l;
  int isnum;
  l = lua_tonumberx(L, 1, &isnum);
  if (isnum && l >= 0) {
    d = l;
  } else {
    return 0;
  }
  n = lua_fixedlstring(L, 2, crypto_stream_NONCEBYTES, "Nonce must be %d bytes.");
  k = lua_fixedlstring(L, 3, crypto_stream_KEYBYTES, "Key must be %d bytes.");
  c = alloc_str(L, d);
  if (!c) return 0;
  crypto_stream(c, d, n, k);
  lua_pushlstring(L, (i8*)c, d);
  free_str(L, c, d);
  return 1;
}

static int lua_crypto_stream_xor(lua_State *L)
{
  u8 *m, *c, *n, *k;
  u64 d;
  m = lua_minlstring(L, 1, 0, &d, "Message must be a string.");
  n = lua_fixedlstring(L, 2, crypto_stream_NONCEBYTES, "Nonce must be %d bytes.");
  k = lua_fixedlstring(L, 3, crypto_stream_KEYBYTES, "Key must be %d bytes.");
  c = alloc_str(L, d);
  if (!c) return 0;
  crypto_stream_xor(c, m, d, n, k);
  lua_pushlstring(L, (i8*)c, d);
  free_str(L, c, d);
  return 1;
}

static int lua_crypto_onetimeauth(lua_State *L)
{
  u8 *m, *k, a[crypto_onetimeauth_BYTES];
  u64 mlen;
  m = lua_minlstring(L, 1, 0, &mlen, "Message must be a string.");
  k = lua_fixedlstring(L, 2, crypto_onetimeauth_KEYBYTES, "Key must be %d bytes.");
  crypto_onetimeauth(a, m, mlen, k);
  lua_pushlstring(L, (i8*)a, crypto_onetimeauth_BYTES);
  return 1;
}

static int lua_crypto_onetimeauth_verify(lua_State *L)
{
  u8 *m, *k, *a;
  u64 mlen;
  a = lua_fixedlstring(L, 1, crypto_onetimeauth_BYTES, "Authenticator must be %d bytes.");
  m = lua_minlstring(L, 2, 0, &mlen, "Message must be a string.");
  k = lua_fixedlstring(L, 3, crypto_onetimeauth_KEYBYTES, "Key must be %d bytes.");
  lua_pushboolean(L, crypto_onetimeauth_verify(a, m, mlen, k) + 1);
  return 1;
}

/* auth not implemented in tweetnacl
static int lua_crypto_auth(lua_State *L)
{
  u8 *m, *k, a[crypto_auth_BYTES];
  u64 mlen;
  m = lua_minlstring(L, 1, 0, &mlen, "Message must be a string.");
  k = lua_fixedlstring(L, 2, crypto_auth_KEYBYTES, "Key must be %d bytes.");
  crypto_auth(a, m, mlen, k);
  lua_pushlstring(L, (i8*)a, crypto_auth_BYTES);
  return 1;
}

static int lua_crypto_auth_verify(lua_State *L)
{
  u8 *m, *k, *a;
  u64 mlen;
  a = lua_fixedlstring(L, 1, crypto_auth_BYTES, "Authenticator must be %d bytes.");
  m = lua_minlstring(L, 2, 0, &mlen, "Message must be a string.");
  k = lua_fixedlstring(L, 3, crypto_auth_KEYBYTES, "Key must be %d bytes.");
  lua_pushboolean(L, crypto_auth_verify(a, m, mlen, k) + 1);
  return 1;
}*/

static int lua_crypto_hash(lua_State *L)
{
  u8 *m, h[crypto_hash_BYTES];
  u64 mlen;
  m = lua_minlstring(L, 1, 0, &mlen, "Message must be a string.");
  crypto_hash(h, m, mlen);
  lua_pushlstring(L, (i8*)h, crypto_hash_BYTES);
  return 1;
}

#define FUNC(n, f) lua_pushliteral(L, n);\
  lua_pushcfunction(L, f);\
  lua_rawset(L, -3);
#define NUM(n, x) lua_pushliteral(L, n);\
  lua_pushnumber(L, x);\
  lua_rawset(L, -3);

int luaopen_nacl(lua_State *L)
{
  lua_newtable(L);
  FUNC("randombytes", lua_crypto_randombytes)
  FUNC("verify_16", lua_crypto_verify_16)
  FUNC("verify_32", lua_crypto_verify_32)
  FUNC("secretbox", lua_crypto_secretbox)
  FUNC("secretbox_open", lua_crypto_secretbox_open)
  FUNC("scalarmult", lua_crypto_scalarmult)
  FUNC("scalarmult_base", lua_crypto_scalarmult_base)
  FUNC("box_keypair", lua_crypto_box_keypair)
  FUNC("box_beforenm", lua_crypto_box_beforenm)
  FUNC("box_afternm", lua_crypto_secretbox)
  FUNC("box_afternm_open", lua_crypto_secretbox_open)
  FUNC("box", lua_crypto_box)
  FUNC("box_open", lua_crypto_box_open)
  FUNC("sign_keypair", lua_crypto_sign_keypair)
  FUNC("sign", lua_crypto_sign)
  FUNC("sign_open", lua_crypto_sign_open)
  FUNC("stream", lua_crypto_stream)
  FUNC("stream_xor", lua_crypto_stream_xor)
  FUNC("onetimeauth", lua_crypto_onetimeauth)
  FUNC("onetimeauth_verify", lua_crypto_onetimeauth_verify)
  /*FUNC("auth", lua_crypto_auth)
  FUNC("auth_verify", lua_crypto_auth_verify)*/
  FUNC("hash", lua_crypto_hash)
  NUM("box_PUBLICKEYBYTES", crypto_box_PUBLICKEYBYTES)
  NUM("box_SECRETKEYBYTES", crypto_box_SECRETKEYBYTES)
  NUM("box_NONCEBYTES", crypto_box_NONCEBYTES)
  NUM("box_BEFORENMBYTES", crypto_box_BEFORENMBYTES)
  NUM("box_PREFIXBYTES", crypto_secretbox_PREFIXBYTES)
  NUM("scalarmult_BYTES", crypto_scalarmult_BYTES)
  NUM("scalarmult_SCALARBYTES", crypto_scalarmult_SCALARBYTES)
  NUM("sign_PUBLICKEYBYTES", crypto_sign_PUBLICKEYBYTES)
  NUM("sign_SECRETKEYBYTES", crypto_sign_SECRETKEYBYTES)
  NUM("sign_BYTES", crypto_sign_BYTES)
  NUM("secretbox_KEYBYTES", crypto_secretbox_KEYBYTES)
  NUM("secretbox_NONCEBYTES", crypto_secretbox_NONCEBYTES)
  NUM("secretbox_PREFIXBYTES", crypto_secretbox_PREFIXBYTES)
  NUM("stream_KEYBYTES", crypto_stream_KEYBYTES)
  NUM("stream_NONCEBYTES", crypto_stream_NONCEBYTES)
  NUM("onetimeauth_KEYBYTES", crypto_onetimeauth_KEYBYTES)
  NUM("onetimeauth_BYTES", crypto_onetimeauth_BYTES)
  /*NUM("auth_KEYBYTES", crypto_auth_KEYBYTES)
  NUM("auth_BYTES", crypto_auth_BYTES)*/
  NUM("hash_BYTES", crypto_hash_BYTES)
  return 1;
}
