defmodule ExOqs.Liboqs do
  @moduledoc """
  Main interfacing module for liboqs NIF 
  """
  alias ExOqs.OsUtils

  @on_load :load_lib

  @doc """
  Load liboqs NIF shared library from environment
  """
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

  @doc """
  Return list of enabled SIG algorithms from underlying liboqs library

  ## Example:

    iex> ExOqs.Liboqs.supported_sign_algo()
    [:Dilithium2, :Dilithium3, :Dilithium5, :"ML-DSA-44-ipd", :"ML-DSA-44",
    :"ML-DSA-65-ipd", :"ML-DSA-65", :"ML-DSA-87-ipd", :"ML-DSA-87", :"Falcon-512",
    :"Falcon-1024", :"Falcon-padded-512", :"Falcon-padded-1024",
    :"SPHINCS+-SHA2-128f-simple", :"SPHINCS+-SHA2-128s-simple",
    :"SPHINCS+-SHA2-192f-simple", :"SPHINCS+-SHA2-192s-simple",
    :"SPHINCS+-SHA2-256f-simple", :"SPHINCS+-SHA2-256s-simple",
    :"SPHINCS+-SHAKE-128f-simple", :"SPHINCS+-SHAKE-128s-simple",
    :"SPHINCS+-SHAKE-192f-simple", :"SPHINCS+-SHAKE-192s-simple",
    :"SPHINCS+-SHAKE-256f-simple", :"SPHINCS+-SHAKE-256s-simple", :"KAZ-SIGN-1",
    :"KAZ-SIGN-3", :"KAZ-SIGN-5"]

  """
  def supported_sign_algo() do
    raise "NIF not implemented"
  end

  @doc """
  Generates keypair for given SIG algorithm

  ## Example: 
    iex> ExOqs.Liboqs.generate_sign_keypair(:Dilithium2)
    {:ok,
    {<<56, 189, 105, 230, 201, 243, 243, 0, 69, 157, 86, 113, 62, 90, 8, 73, 89,
       94, 245, 73, 160, 87, 72, 130, 180, 14, 69, 37, 99, 248, 200, 38, 175, 246,
       33, 55, 221, 121, 224, 181, 99, 229, 233, 130, 52, 155, 28, ...>>,
     <<56, 189, 105, 230, 201, 243, 243, 0, 69, 157, 86, 113, 62, 90, 8, 73, 89,
       94, 245, 73, 160, 87, 72, 130, 180, 14, 69, 37, 99, 248, 200, 38, 255, 240,
       36, 110, 21, 86, 162, 4, 177, 3, 105, 51, 158, 206, ...>>}}
  """
  @spec generate_sign_keypair(atom()) :: {:ok, {binary(), binary()}} | {:error, atom()}
  def generate_sign_keypair(algo) do
    raise "NIF not implemented"
  end

  @doc """
  Sign a given data and returns the signature

  ## Example: 
      iex> {:ok, {public, private}} = ExOqs.Liboqs.generate_sign_keypair(:Dilithium2)
      {:ok,
      {<<56, 189, 105, 230, 201, 243, 243, 0, 69, 157, 86, 113, 62, 90, 8, 73, 89,
         94, 245, 73, 160, 87, 72, 130, 180, 14, 69, 37, 99, 248, 200, 38, 175, 246,
         33, 55, 221, 121, 224, 181, 99, 229, 233, 130, 52, 155, 28, ...>>,
       <<56, 189, 105, 230, 201, 243, 243, 0, 69, 157, 86, 113, 62, 90, 8, 73, 89,
         94, 245, 73, 160, 87, 72, 130, 180, 14, 69, 37, 99, 248, 200, 38, 255, 240,
         36, 110, 21, 86, 162, 4, 177, 3, 105, 51, 158, 206, ...>>}}

      iex> {:ok, signature} = ExOqs.Liboqs.sign(:Dilithium2, private, "Data requires integrity") 
      {:ok,
      <<116, 185, 55, 145, 246, 98, 208, 222, 0, 101, 105, 183, 173, 20, 251, 206,
       78, 210, 158, 16, 211, 171, 211, 2, 120, 2, 91, 70, 215, 205, 65, 49, 34,
       135, 200, 59, 108, 247, 149, 82, 90, 82, 253, 220, 175, 135, 13, 83, ...>>}
  """
  @spec sign(atom(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def sign(algo, privKey, data) do
    raise "NIF not implemented"
  end

  @doc """
  Verify a signature 

  ## Example: 
    iex> res = ExOqs.Liboqs.verify(signature, :Dilithium2, public, "Data requires integrity") 
        {:ok, :verify_success}

    iex> res = ExOqs.Liboqs.verify(signature, :Dilithium2, public, "Data requires integrity but modified") 
        {:ok, {:verify_error, -1}}
  """
  @spec verify(binary(), atom(), binary(), binary()) ::
          {:ok, :verify_success} | {:ok, {:verify_error, integer()}}
  def verify(signature, algo, pubKey, data) do
    raise "NIF not implemented"
  end

  @doc """
  Returns list of supported KEM algorithm from underlying liboqs library 

  ## Example: 

    iex> ExOqs.Liboqs.supported_kem_algo()
        [:"BIKE-L1", :"BIKE-L3", :"BIKE-L5", :"Classic-McEliece-348864",
         :"Classic-McEliece-348864f", :"Classic-McEliece-460896",
         :"Classic-McEliece-460896f", :"Classic-McEliece-6688128",
         :"Classic-McEliece-6688128f", :"Classic-McEliece-6960119",
         :"Classic-McEliece-6960119f", :"Classic-McEliece-8192128",
         :"Classic-McEliece-8192128f", :"HQC-128", :"HQC-192", :"HQC-256", :Kyber512,
         :Kyber768, :Kyber1024, :"ML-KEM-512-ipd", :"ML-KEM-512", :"ML-KEM-768-ipd",
         :"ML-KEM-768", :"ML-KEM-1024-ipd", :"ML-KEM-1024", :sntrup761,
         :"FrodoKEM-640-AES", :"FrodoKEM-640-SHAKE", :"FrodoKEM-976-AES",
         :"FrodoKEM-976-SHAKE", :"FrodoKEM-1344-AES", :"FrodoKEM-1344-SHAKE"]
  """
  @spec supported_kem_algo() :: [atom()]
  def supported_kem_algo() do
    raise "NIF not implemented"
  end

  @doc """
  Generate KEM keypoir of specific algorithm

  ## Example: 

    iex> {:ok, {public, private}} = ExOqs.Liboqs.generate_kem_keypair(:Kyber768)
    {:ok,
    {<<197, 163, 78, 148, 197, 11, 136, 34, 100, 8, 168, 107, 125, 224, 199, 160,
      148, 164, 108, 20, 10, 242, 101, 161, 245, 113, 160, 215, 233, 1, 133, 214,
      96, 120, 147, 126, 198, 12, 131, 79, 1, 37, 65, 3, 82, 214, 2, ...>>,
    <<107, 179, 144, 98, 131, 72, 6, 51, 117, 115, 50, 136, 178, 49, 5, 44, 203,
      205, 70, 107, 143, 56, 89, 185, 104, 240, 169, 79, 149, 131, 34, 163, 126,
      241, 249, 61, 88, 211, 69, 101, 135, 148, 99, 178, 167, 144, ...>>}}

  """
  @spec generate_kem_keypair(atom()) :: {:ok, {binary(), binary()}} | {:error, atom()}
  def generate_kem_keypair(algo) do
    raise "NIF not implemented"
  end

  @doc """
  Encapsulate KEM with recipient public key

  ## Example: 

    iex> {:ok, {shared_cipher, shared_key}} = ExOqs.Liboqs.encaps(:Kyber768, public)
    {:ok,
      {<<78, 103, 59, 120, 122, 155, 20, 23, 121, 246, 195, 175, 240, 176, 58, 34,
         67, 236, 191, 252, 172, 117, 7, 92, 192, 66, 61, 142, 87, 61, 62, 79, 174,
         218, 139, 250, 154, 81, 72, 60, 249, 121, 174, 7, 125, 176, 74, ...>>,
       <<80, 216, 149, 77, 19, 146, 165, 120, 185, 199, 75, 103, 2, 181, 95, 249, 76,
         221, 12, 206, 58, 155, 222, 182, 129, 54, 27, 80, 189, 199, 22, 66>>}}
  """
  @spec encaps(atom(), binary()) :: {:ok, {binary(), binary()}} | {:error, atom()}
  def encaps(algo, pubKey) do
    raise "NIF not implemented"
  end

  @doc """
  Decapsulate KEM with recipient private key. Same shared key shall be obtained from
  encaps process above

  ## Example: 
    iex> {:ok, shared_key} = ExOqs.Liboqs.decaps(:Kyber768, private)
          {:ok,
           <<80, 216, 149, 77, 19, 146, 165, 120, 185, 199, 75, 103, 2, 181, 95, 249, 76,
             221, 12, 206, 58, 155, 222, 182, 129, 54, 27, 80, 189, 199, 22, 66>>}
  """
  @spec decaps(atom(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def decaps(algo, shared_cipher, privKey) do
    raise "NIF not implemented"
  end
end
