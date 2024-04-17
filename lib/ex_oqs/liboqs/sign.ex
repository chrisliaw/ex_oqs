defmodule ExOqs.Liboqs.Sign do
  alias ExOqs.Liboqs

  def supported_algo() do
    Liboqs.supported_sign_algo()
  end

  def generate_keypair(algo) do
    Liboqs.generate_sign_keypair(algo)
  end

  def sign(algo, privKey, data) do
    Liboqs.sign(algo, privKey, data)
  end

  def verify(signature, algo, pubKey, data) do
    Liboqs.verify(signature, algo, pubKey, data)
  end
end
