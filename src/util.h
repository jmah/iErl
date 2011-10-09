
#ifndef EMONK_UTIL_H
#define EMONK_UTIL_H

#include <erl_nif.h>
#include <jsapi.h>

#include "alias.h"

jsval to_js(ErlNifEnv* env, JSContext* cx, ENTERM term);
ENTERM to_erl(ErlNifEnv* env, JSContext* cx, jsval val);

ENTERM util_mk_atom(ErlNifEnv* env, const char* atom);
ENTERM util_mk_binary(ErlNifEnv* env, const char* chars, size_t len);
ENTERM util_mk_ok(ErlNifEnv* env, ENTERM value);
ENTERM util_mk_error(ErlNifEnv* env, const char* reason); // use only with a fixed set of reasons
ENTERM util_mk_error_str(ErlNifEnv* env, const char* reason);  // OK with arbitrary reasons

void util_debug_jsval(JSContext* cx, jsval val);

#endif // Included util.h
