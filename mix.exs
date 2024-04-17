defmodule ExOqs.MixProject do
  use Mix.Project

  def project do
    [
      name: "ExOqs",
      app: :ex_oqs,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      source_url: "https://github.com/chrisliaw/ex_oqs"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {ExOqs.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end

  defp description() do
    "Elixir wrapper for liboqs C library which is the open source implementation of NIST Post Quantum / Quantum Safe algorithm for Elixir ecosystem"
  end

  defp package() do
    [
      # These are the default files included in the package
      files: ~w(lib native_lib .formatter.exs mix.exs README* readme* LICENSE*
                license* CHANGELOG* changelog* src c_src),
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/chrisliaw/ex_oqs"}
    ]
  end
end
