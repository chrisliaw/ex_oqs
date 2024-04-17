defmodule ExOqs.Liboqs.Sign do
  @moduledoc """
  Module namespaced the liboqs SIG API
  """

  alias ExOqs.Liboqs

  @spec supported_algo() :: [atom()]
  def supported_algo() do
    Liboqs.supported_sign_algo()
  end

  @doc """
  Generate keypair of given SIG algorithm

  ## Example

    iex> ExOqs.Liboqs.Sign.generate_keypair(:Dilithium2)
    {:ok, {<<2,3,4,..>>, <<20,41,24,211,..>>}}

  """
  @spec generate_keypair(atom()) :: {:ok, {binary(), binary()}}
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
