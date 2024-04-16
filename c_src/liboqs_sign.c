

#include "oqs/oqs.h"
#include <erl_nif.h>

static ERL_NIF_TERM supported_algo(ErlNifEnv *env, int argc,
                                   const ERL_NIF_TERM argv[]) {

  ERL_NIF_TERM *list = enif_alloc(OQS_SIG_algs_length * sizeof(ERL_NIF_TERM));
  for (int i = 0; i < OQS_SIG_algs_length; i++) {
    ERL_NIF_TERM *exist = enif_alloc(sizeof(ERL_NIF_TERM));
    // list[i] = enif_make_atom(env, OQS_SIG_alg_identifier(i));
    int res = enif_make_existing_atom(env, OQS_SIG_alg_identifier(i), exist,
                                      ERL_NIF_UTF8);
    if (res) {
      list[i] = *exist;
    } else {

      list[i] = enif_make_atom(env, OQS_SIG_alg_identifier(i));
      enif_free(exist);
    }
  }

  return enif_make_list_from_array(env, list, OQS_SIG_algs_length);
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

  int rv = enif_get_atom_length(env, algo, &len, ERL_NIF_UTF8);
  // printf("rv 1 : %d\n", rv);
  if (rv) {
    // printf("size : %d\n", len);
    name = enif_alloc(sizeof(char) * len + 1);
    rv = enif_get_atom(env, algo, name, len + 1, ERL_NIF_UTF8);
  }

  // printf("rv 2 : %d\n", rv);
  if (rv > 0) {
    printf("got algo : %s\n", name);
    OQS_SIG *sig = OQS_SIG_new(name);
    if (sig == NULL) {
      printf("SIG null\n");
      fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "SIG_null"));
      goto cleanup;
    }

    enif_alloc_binary(sig->length_public_key, &pubKey);
    enif_alloc_binary(sig->length_secret_key, &privKey);
    rc = OQS_SIG_keypair(sig, pubKey.data, privKey.data);
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

    printf("pubkey gen : ");
    for (int i = 0; i < pubKey.size; i++)
      printf("%02x", pubKey.data[i]);
    printf("\n");

    printf("privkey gen : ");
    for (int i = 0; i < privKey.size; i++)
      printf("%02x", privKey.data[i]);
    printf("\n");

    enif_release_binary(&pubKey);
    enif_release_binary(&privKey);
  }

cleanup:
  if (name != NULL)
    enif_free(name);

  return fret;
}

static ERL_NIF_TERM sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {

  ERL_NIF_TERM algo = argv[0];
  ERL_NIF_TERM privKey = argv[1];
  ERL_NIF_TERM data = argv[2];

  unsigned len = 0;
  char *name = NULL;

  ErlNifBinary dataBin;
  ErlNifBinary privKeyBin;

  ErlNifBinary signature;
  size_t signature_length = 0;

  OQS_STATUS rc;
  int rv = 0;
  ERL_NIF_TERM fret;

  rv = enif_is_binary(env, data);
  if (!rv) {
    fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "binary_data_expected"));
    goto cleanup;
  }

  rv = enif_is_binary(env, privKey);
  if (!rv) {
    fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "binary_private_key_expected"));
    goto cleanup;
  }

  rv = enif_inspect_binary(env, data, &dataBin);
  if (!rv) {
    fret =
        enif_make_tuple2(env, enif_make_atom(env, "error"),
                         enif_make_atom(env, "data_binary_conversion_error"));
    goto cleanup;
  }

  rv = enif_inspect_binary(env, privKey, &privKeyBin);
  if (!rv) {
    fret = enif_make_tuple2(
        env, enif_make_atom(env, "error"),
        enif_make_atom(env, "private_key_binary_conversion_error"));
    goto cleanup;
  }

  printf("privkey sign : ");
  for (int i = 0; i < privKeyBin.size; i++)
    printf("%02x", privKeyBin.data[i]);
  printf("\n");

  printf("Before getting atom length\n");
  rv = enif_get_atom_length(env, algo, &len, ERL_NIF_UTF8);
  if (!rv && len <= 0) {
    fret = enif_make_tuple2(
        env, enif_make_atom(env, "error"),
        enif_make_tuple2(env, enif_make_atom(env, "error_getting_algo_name"),
                         enif_make_int(env, len)));
    goto cleanup;

  } else {
    printf("got algo atom length : %d\n", len);
    name = enif_alloc(sizeof(char) * len + 1);
    rv = enif_get_atom(env, algo, name, len + 1, ERL_NIF_UTF8);
  }

  if (rv > 0) {
    printf("got algo : %s\n", name);
    OQS_SIG *sig = OQS_SIG_new(name);
    if (sig == NULL) {
      printf("SIG null\n");
      fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "SIG_null"));
      goto cleanup;
    }

    enif_alloc_binary(sig->length_signature, &signature);

    rc = OQS_SIG_sign(sig, signature.data, &signature_length, dataBin.data,
                      dataBin.size, privKeyBin.data);
    if (rc != OQS_SUCCESS) {
      printf("OQS signing error!\n");
      fret = enif_make_tuple2(
          env, enif_make_atom(env, "error"),
          enif_make_tuple2(env, enif_make_atom(env, "signing_error"),
                           enif_make_int(env, rc)));
      goto cleanup;
    }

    printf("signature length : %lu\n", signature_length);

    fret = enif_make_tuple2(env, enif_make_atom(env, "ok"),
                            enif_make_binary(env, &signature));
  } else {
    fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "failed_to_get_algo_name"));
  }

cleanup:
  enif_release_binary(&signature);
  enif_release_binary(&dataBin);
  enif_release_binary(&privKeyBin);

  return fret;
}

static ERL_NIF_TERM verify(ErlNifEnv *env, int argc,
                           const ERL_NIF_TERM argv[]) {

  ERL_NIF_TERM signature = argv[0];
  ERL_NIF_TERM algo = argv[1];
  ERL_NIF_TERM pubKey = argv[2];
  ERL_NIF_TERM data = argv[3];

  unsigned len = 0;
  char *name = NULL;

  ErlNifBinary dataBin;
  ErlNifBinary pubKeyBin;
  ErlNifBinary signBin;

  OQS_STATUS rc;
  int rv = 0;
  ERL_NIF_TERM fret;

  rv = enif_is_binary(env, signature);
  if (!rv) {
    fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "binary_signature_expected"));
    goto cleanup;
  }

  rv = enif_is_binary(env, data);
  if (!rv) {
    fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "binary_data_expected"));
    goto cleanup;
  }

  rv = enif_is_binary(env, pubKey);
  if (!rv) {
    fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "binary_public_key_expected"));
    goto cleanup;
  }

  rv = enif_inspect_binary(env, signature, &signBin);
  if (!rv) {
    fret = enif_make_tuple2(
        env, enif_make_atom(env, "error"),
        enif_make_atom(env, "signature_binary_conversion_error"));
    goto cleanup;
  }

  rv = enif_inspect_binary(env, data, &dataBin);
  if (!rv) {
    fret =
        enif_make_tuple2(env, enif_make_atom(env, "error"),
                         enif_make_atom(env, "data_binary_conversion_error"));
    goto cleanup;
  }

  rv = enif_inspect_binary(env, pubKey, &pubKeyBin);
  if (!rv) {
    fret = enif_make_tuple2(
        env, enif_make_atom(env, "error"),
        enif_make_atom(env, "public_key_binary_conversion_error"));
    goto cleanup;
  }

  printf("pubkey verify : ");
  for (int i = 0; i < pubKeyBin.size; i++)
    printf("%02x", pubKeyBin.data[i]);
  printf("\n");

  rv = enif_get_atom_length(env, algo, &len, ERL_NIF_UTF8);
  if (rv) {
    name = enif_alloc(sizeof(char) * len + 1);
    rv = enif_get_atom(env, algo, name, len + 1, ERL_NIF_UTF8);
  }

  if (rv > 0) {
    printf("got algo : %s\n", name);
    OQS_SIG *sig = OQS_SIG_new(name);
    if (sig == NULL) {
      printf("SIG null\n");
      fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                              enif_make_atom(env, "SIG_null"));
      goto cleanup;
    }

    printf("data size : %lu\n", dataBin.size);
    printf("signature size : %lu\n", signBin.size);

    rc = OQS_SIG_verify(sig, dataBin.data, dataBin.size, signBin.data,
                        signBin.size, pubKeyBin.data);
    if (rc != OQS_SUCCESS) {
      printf("OQS verification error!\n");
      fret = enif_make_tuple2(
          env, enif_make_atom(env, "ok"),
          enif_make_tuple2(env, enif_make_atom(env, "verify_error"),
                           enif_make_int(env, rc)));
      goto cleanup;
    } else {

      fret = enif_make_tuple2(env, enif_make_atom(env, "ok"),
                              enif_make_atom(env, "verify_success"));
    }

  } else {
    fret = enif_make_tuple2(env, enif_make_atom(env, "error"),
                            enif_make_atom(env, "failed_to_get_algo_name"));
  }

cleanup:
  enif_release_binary(&signBin);
  enif_release_binary(&dataBin);
  enif_release_binary(&pubKeyBin);

  return fret;
}

static ErlNifFunc nif_funcs[] = {
    {"supported_algo", 0, supported_algo},
    {"generate_keypair", 1, generate_keypair},
    {"sign", 3, sign},
    {"verify", 4, verify},

};

ERL_NIF_INIT(Elixir.ExOqs.Liboqs.Sign, nif_funcs, NULL, NULL, NULL, NULL)
