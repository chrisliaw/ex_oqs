

#include "oqs/oqs.h"
#include <erl_nif.h>

static ERL_NIF_TERM supported_algo(ErlNifEnv *env, int argc,
                                   const ERL_NIF_TERM argv[]) {

  ERL_NIF_TERM *list = enif_alloc(OQS_KEM_algs_length * sizeof(ERL_NIF_TERM));
  for (int i = 0; i < OQS_KEM_algs_length; i++) {
    ERL_NIF_TERM *exist = enif_alloc(sizeof(ERL_NIF_TERM));
    // list[i] = enif_make_atom(env, OQS_KEM_alg_identifier(i));
    int res = enif_make_existing_atom(env, OQS_KEM_alg_identifier(i), exist,
                                      ERL_NIF_UTF8);
    if (res) {
      list[i] = *exist;
    } else {

      list[i] = enif_make_atom(env, OQS_KEM_alg_identifier(i));
      enif_free(exist);
    }
  }

  OQS_destroy();

  return enif_make_list_from_array(env, list, OQS_KEM_algs_length);
}

static ERL_NIF_TERM generate_keypair(ErlNifEnv *env, int argc,
                                     const ERL_NIF_TERM argv[]) {

  ERL_NIF_TERM algo = argv[0];

  unsigned len = 0;
  char *name = NULL;
  ErlNifBinary pubKey;
  ErlNifBinary privKey;
  OQS_STATUS rc;
  ERL_NIF_TERM fret;
  OQS_KEM *kem = NULL;

  int rv = enif_get_atom_length(env, algo, &len, ERL_NIF_UTF8);
  if (rv) {
    name = enif_alloc(sizeof(char) * len + 1);
    rv = enif_get_atom(env, algo, name, len + 1, ERL_NIF_UTF8);
  }

  if (rv > 0) {
    printf("got algo : %s\n", name);
    kem = OQS_KEM_new(name);
    if (kem == NULL) {
      printf("KEM null\n");
      fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "KEM_null"));
      goto cleanup;
    }

    enif_alloc_binary(kem->length_public_key, &pubKey);
    enif_alloc_binary(kem->length_secret_key, &privKey);
    rc = OQS_KEM_keypair(kem, pubKey.data, privKey.data);
    if (rc != OQS_SUCCESS) {
      printf("OQS keypair error!\n");
      fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "OQS_keypair_error"));
      goto cleanup;
    }

    fret =
        enif_make_tuple2(env, enif_make_atom(env, "ok"),
                         enif_make_tuple2(env, enif_make_binary(env, &pubKey),
                                          enif_make_binary(env, &privKey)));

    enif_release_binary(&pubKey);
    enif_release_binary(&privKey);
  }

cleanup:
  if (name != NULL)
    enif_free(name);

  if (kem != NULL)
    OQS_KEM_free(kem);

  return fret;
}

static ERL_NIF_TERM encapsulate(ErlNifEnv *env, int argc,
                                const ERL_NIF_TERM argv[]) {

  ERL_NIF_TERM algo = argv[0];
  ERL_NIF_TERM pubKey = argv[1];

  unsigned len = 0;
  char *name = NULL;
  OQS_KEM *kem = NULL;

  ErlNifBinary sharedCipher;
  ErlNifBinary sharedKey;
  ErlNifBinary pubKeyBin;

  OQS_STATUS rc;
  int rv = 0;
  ERL_NIF_TERM fret;

  rv = enif_is_binary(env, pubKey);
  if (!rv) {
    fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "binary_public_key_expected"));
    goto cleanup;
  }

  rv = enif_inspect_binary(env, pubKey, &pubKeyBin);
  if (!rv) {
    fret = enif_make_tuple2(
        env, enif_make_atom(env, "error"),
        enif_make_atom(env, "public_key_binary_conversion_error"));
    goto cleanup;
  }

  rv = enif_get_atom_length(env, algo, &len, ERL_NIF_UTF8);
  if (!rv && len <= 0) {
    fret = enif_make_tuple2(
        env, enif_make_atom(env, "error"),
        enif_make_tuple2(env, enif_make_atom(env, "error_getting_algo_name"),
                         enif_make_int(env, len)));
    goto cleanup;

  } else {
    name = enif_alloc(sizeof(char) * len + 1);
    rv = enif_get_atom(env, algo, name, len + 1, ERL_NIF_UTF8);
  }

  if (rv > 0) {
    kem = OQS_KEM_new(name);
    if (kem == NULL) {
      fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "KEM_null"));
      goto cleanup;
    }

    enif_alloc_binary(kem->length_shared_secret, &sharedKey);
    enif_alloc_binary(kem->length_ciphertext, &sharedCipher);

    rc = OQS_KEM_encaps(kem, sharedCipher.data, sharedKey.data, pubKeyBin.data);
    if (rc != OQS_SUCCESS) {
      fret = enif_make_tuple2(
          env, enif_make_atom(env, "error"),
          enif_make_tuple2(env, enif_make_atom(env, "encaps_error"),
                           enif_make_int(env, rc)));
      goto cleanup;
    }

    fret = enif_make_tuple2(
        env, enif_make_atom(env, "ok"),
        enif_make_tuple2(env, enif_make_binary(env, &sharedCipher),
                         enif_make_binary(env, &sharedKey)));
  } else {
    fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "failed_to_get_algo_name"));
  }

cleanup:
  enif_release_binary(&sharedKey);
  enif_release_binary(&sharedCipher);
  enif_release_binary(&pubKeyBin);

  if (name != NULL)
    enif_free(name);

  if (kem != NULL)
    OQS_KEM_free(kem);

  return fret;
}

static ERL_NIF_TERM decapsulate(ErlNifEnv *env, int argc,
                                const ERL_NIF_TERM argv[]) {

  ERL_NIF_TERM algo = argv[0];
  ERL_NIF_TERM sharedCipher = argv[1];
  ERL_NIF_TERM privKey = argv[2];

  unsigned len = 0;
  char *name = NULL;
  OQS_KEM *kem = NULL;

  ErlNifBinary sharedKeyBin;
  ErlNifBinary sharedCipherBin;
  ErlNifBinary privKeyBin;

  OQS_STATUS rc;
  int rv = 0;
  ERL_NIF_TERM fret;

  rv = enif_is_binary(env, sharedCipher);
  if (!rv) {
    fret =
        enif_make_tuple2(env, enif_make_atom(env, "error"),
                         enif_make_atom(env, "binary_shared_cipher_expected"));
    goto cleanup;
  }

  rv = enif_is_binary(env, privKey);
  if (!rv) {
    fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "binary_private_key_expected"));
    goto cleanup;
  }

  rv = enif_inspect_binary(env, sharedCipher, &sharedCipherBin);
  if (!rv) {
    fret = enif_make_tuple2(
        env, enif_make_atom(env, "error"),
        enif_make_atom(env, "shared_cipher_binary_conversion_error"));
    goto cleanup;
  }

  rv = enif_inspect_binary(env, privKey, &privKeyBin);
  if (!rv) {
    fret = enif_make_tuple2(
        env, enif_make_atom(env, "error"),
        enif_make_atom(env, "private_key_binary_conversion_error"));
    goto cleanup;
  }

  rv = enif_get_atom_length(env, algo, &len, ERL_NIF_UTF8);
  if (rv) {
    name = enif_alloc(sizeof(char) * len + 1);
    rv = enif_get_atom(env, algo, name, len + 1, ERL_NIF_UTF8);
  }

  if (rv > 0) {
    kem = OQS_KEM_new(name);
    if (kem == NULL) {
      fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "KEM_null"));
      goto cleanup;
    }

    enif_alloc_binary(kem->length_shared_secret, &sharedKeyBin);

    rc = OQS_KEM_decaps(kem, sharedKeyBin.data, sharedCipherBin.data,
                        privKeyBin.data);
    if (rc != OQS_SUCCESS) {
      fret = enif_make_tuple2(
          env, enif_make_atom(env, "ok"),
          enif_make_tuple2(env, enif_make_atom(env, "verify_error"),
                           enif_make_int(env, rc)));
      goto cleanup;
    } else {

      fret = enif_make_tuple2(env, enif_make_atom(env, "ok"),
                              enif_make_binary(env, &sharedKeyBin));
    }
  } else {
    fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "failed_to_get_algo_name"));
  }

cleanup:
  enif_release_binary(&sharedKeyBin);
  enif_release_binary(&sharedCipherBin);
  enif_release_binary(&privKeyBin);

  if (name != NULL)
    enif_free(name);

  if (kem != NULL)
    OQS_KEM_free(kem);

  return fret;
}

static ErlNifFunc nif_funcs[] = {
    {"supported_algo", 0, supported_algo},
    {"generate_keypair", 1, generate_keypair},
    {"encaps", 2, encapsulate},
    {"decaps", 3, decapsulate},

};

ERL_NIF_INIT(Elixir.ExOqs.Liboqs.KEM, nif_funcs, NULL, NULL, NULL, NULL)
