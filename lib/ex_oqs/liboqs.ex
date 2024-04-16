defmodule ExOqs.Liboqs do
  @on_load :load_lib
  def load_lib do
    :erlang.load_nif(~c"./c_src/liboqs", 0)
  end

  def supported_sign_algo() do
    raise "NIF not implemented"
  end
end
