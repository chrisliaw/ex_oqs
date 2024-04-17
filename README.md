# ExOqs

ExOqs is wrapper for [Open Source Quantum Safe Toolkit (liboqs)](https://github.com/open-quantum-safe/liboqs) that consolidated NIST Post Quantum Cryptography into single toolkit.

The wrapper allow Elixir modules can utilize the PQC for next generation data protection which protects data from quantum computer attack.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `ex_oqs` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_oqs, "~> 0.1.0"}
  ]
end
```

## Included liboqs Version

There are two platforms that are "batteries-included" which can be use out of the box (I hope) which are

- Linux X86_64 (build on Docker running Ubuntu Jammy with default libgmp and OpenSSL library comes with the OS)
- Mac OS arm64 (build on M1 chip)

On those two platforms, ExOqs should just work. However for other platform which I have no access to, a liboqs static library may need to build first before the library will work. Unfortunately the build of the liboqs library is outside the scope of this library. If it comes to this, you might want to start from [liboqs main site first](https://github.com/open-quantum-safe/liboqs)

The liboqs version mapping as follow:

- ExOqs v0.1.0 - liboqs v0.10.0 with KAZ-SIGN PQC algorithm patch. (Patch of KAZ-SIGN is available on liboqs fork [here, under branch 0.10.0_kaz-sign](https://github.com/Antrapol/liboqs))
