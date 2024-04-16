defmodule ExOqs.Liboqs.Sign do
  @on_load :load_lib
  def load_lib do
    :erlang.load_nif(~c"./c_src/liboqs", 0)
  end

  def supported_algo() do
    raise "NIF not implemented"
  end

  def generate_keypair(algo) do
    raise "NIF not implemented"
  end

  def sign(algo, privKey, data) do
    raise "NIF not implemented"
  end

  def verify(signature, algo, pubKey, data) do
    raise "NIF not implemented"
  end
end
