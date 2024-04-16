defmodule ExOqsTest do
  use ExUnit.Case
  doctest ExOqs

  @tag timeout: :infinity
  test "regression test specific algo" do
    # algo = :"KAZ-SIGN-5"
    # algo = :"KAZ-SIGN-3"
    # algo = :"KAZ-SIGN-5"
    # algo = :"KAZ-SIGN-1"
    # algo = :"Falcon-padded-512"
    # algo = :"Falcon-padded-1024"
    # algo = :Dilithium5

    Enum.map(
      [
        :"KAZ-SIGN-1",
        :"KAZ-SIGN-3",
        :"KAZ-SIGN-5",
        :Dilithium2,
        :Dilitium3,
        :Dilithium5,
        :"Falcon-padded-512",
        :"Falcon-padded-1024"
      ],
      fn algo ->
        for x <- 0..1000 do
          IO.puts("Count : #{x}")
          res = ExOqs.Liboqs.Sign.generate_keypair(algo)
          IO.inspect(res)
          {:ok, {pubkey, privkey}} = res
          IO.puts("pubkey : #{inspect(pubkey)}")
          IO.puts("privkey : #{inspect(privkey)}")

          {:ok, sign} = sres = ExOqs.Liboqs.Sign.sign(algo, privkey, "testing")
          IO.inspect(sres)

          vres = ExOqs.Liboqs.Sign.verify(sign, algo, pubkey, "testing")
          IO.inspect(vres)
          {:ok, :verify_success} = vres

          vres2 = ExOqs.Liboqs.Sign.verify(sign, algo, pubkey, "testing 123")
          IO.inspect(vres2)
          {:ok, {:verify_error, _}} = vres2
        end
      end
    )
  end

  test "liboqs signing API" do
    algo = ExOqs.Liboqs.Sign.supported_algo()
    IO.inspect(algo)
    assert(length(algo) > 0)

    algo = :"KAZ-SIGN-1"
    # algo = :"Falcon-padded-512"
    # algo = :Dilithium5

    res = ExOqs.Liboqs.Sign.generate_keypair(algo)
    IO.inspect(res)
    {:ok, {pubkey, privkey}} = res
    IO.puts("pubkey : #{inspect(pubkey)}")
    IO.puts("privkey : #{inspect(privkey)}")

    {:ok, sign} = sres = ExOqs.Liboqs.Sign.sign(algo, privkey, "testing")
    IO.inspect(sres)

    vres = ExOqs.Liboqs.Sign.verify(sign, algo, pubkey, "testing")
    IO.inspect(vres)
    {:ok, :verify_success} = vres

    vres2 = ExOqs.Liboqs.Sign.verify(sign, algo, pubkey, "testing 123")
    IO.inspect(vres2)
    {:ok, {:verify_error, _}} = vres2
  end

  test "all liboqs signing algo" do
    algo = ExOqs.Liboqs.Sign.supported_algo()
    IO.inspect(algo)
    assert(length(algo) > 0)

    ralgo =
      Enum.reject(algo, fn x ->
        # seems this two algo requires any of the inputs to be fixed size
        x == :"Falcon-512" || x == :"Falcon-1024"
      end)

    IO.puts("algo list : #{inspect(ralgo)}")

    Enum.map(ralgo, fn x ->
      IO.puts("testing algo #{inspect(x)}")
      res = ExOqs.Liboqs.Sign.generate_keypair(x)
      IO.inspect(res)
      {:ok, {pubkey, privkey}} = res
      IO.puts("pubkey : #{inspect(pubkey)}")
      IO.puts("privkey : #{inspect(privkey)}")

      {:ok, sign} = sres = ExOqs.Liboqs.Sign.sign(x, privkey, "testing")
      IO.inspect(sres)

      vres = ExOqs.Liboqs.Sign.verify(sign, x, pubkey, "testing")
      IO.inspect(vres)
      {:ok, :verify_success} = vres

      vres2 = ExOqs.Liboqs.Sign.verify(sign, x, pubkey, "testing 123")
      IO.inspect(vres2)
      {:ok, {:verify_error, _}} = vres2
    end)
  end
end
