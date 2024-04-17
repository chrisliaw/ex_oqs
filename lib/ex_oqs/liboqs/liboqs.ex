defmodule ExOqs.Liboqs do
  alias ExOqs.OsUtils

  @on_load :load_lib
  def load_lib do
    with {:ok, {os, arch}} <- OsUtils.os_info() do
      :erlang.load_nif(
        Path.join(
          Path.expand(Path.dirname(__ENV__.file)),
          "../../../native_lib/#{os}/#{arch}/liboqs"
        ),
        0
      )
    else
      res -> raise RuntimeError, message: "Unknown platform #{res}"
    end
  end

  def supported_sign_algo() do
    raise "NIF not implemented"
  end

  def generate_sign_keypair(algo) do
    raise "NIF not implemented"
  end

  def sign(algo, privKey, data) do
    raise "NIF not implemented"
  end

  def verify(signature, algo, pubKey, data) do
    raise "NIF not implemented"
  end

  def supported_kem_algo() do
    raise "NIF not implemented"
  end

  def generate_kem_keypair(algo) do
    raise "NIF not implemented"
  end

  def encaps(algo, pubKey) do
    raise "NIF not implemented"
  end

  def decaps(algo, shared_cipher, privKey) do
    raise "NIF not implemented"
  end
end

