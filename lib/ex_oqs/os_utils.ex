defmodule ExOqs.OsUtils do
  def os_info do
    str = to_string(:erlang.system_info(:system_architecture))

    with {:ok, os} <- detect_os(str),
         {:ok, arch} <- detect_arch(str) do
      {:ok, {os, arch}}
    end
  end

  @spec detect_os(String.t()) :: {:ok, :linux | :mac} | {:error, binary()}
  def detect_os(str) do
    cond do
      String.contains?(str, "darwin") -> {:ok, :mac}
      String.contains?(str, "linux") -> {:ok, :linux}
      true -> {:error, str}
    end
  end

  def detect_arch(str) do
    cond do
      String.contains?(str, "aarch64") -> {:ok, :arm64}
      String.contains?(str, "x86_64") -> {:ok, :x86_64}
      true -> {:error, str}
    end
  end
end
