defmodule ExOqs.Liboqs.KEM do
  alias ExOqs.Liboqs

  def supported_algo() do
    Liboqs.supported_kem_algo()
  end

  def generate_keypair(algo) do
    Liboqs.generate_kem_keypair(algo)
  end

  def encaps(algo, pubKey) do
    Liboqs.encaps(algo, pubKey)
  end

  def decaps(algo, shared_cipher, privKey) do
    Liboqs.decaps(algo, shared_cipher, privKey)
  end
end
