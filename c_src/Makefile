
UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
	CFLAGS= -fPIC -I include -I ~/.asdf/installs/erlang/26.2.1/erts-14.2.1/include -shared -o liboqs.so liboqs_sign.c -L ../native_lib/linux/ -l:liboqs.a -l:libgmp.so -l:libcrypto.so
endif
ifeq ($(UNAME), Darwin)
	CFLAGS = -fPIC -Iinclude -I/Users/chris/.asdf/installs/erlang/26.2.1/erts-14.2.1/include -lgmp -lcrypto -o liboqs.so liboqs_sign.c /Users/chris/01.Workspaces/02.Code-Factory/08-Workspace/elixir/08.WS/ex_oqs/native_lib/mac/aarch64/liboqs.a -bundle -bundle_loader /Users/chris/.asdf/installs/erlang/26.2.1/erts-14.2.1/bin/beam.smp
endif


liboqs.so: liboqs_sign.c
	gcc $(CFLAGS)

clean:
	rm *.so
