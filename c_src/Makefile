
UNAME := $(shell uname)
ARCH := $(shell uname -m)
ifeq ($(UNAME), Linux)
	CFLAGS= -fPIC -I include -I ~/.asdf/installs/erlang/26.2.1/erts-14.2.1/include -shared -o ../native_lib/linux/$(ARCH)/liboqs.so liboqs.c -L ../native_lib/linux/$(ARCH) -l:liboqs.a -l:libgmp.so -l:libcrypto.so
endif
ifeq ($(UNAME), Darwin)
	CFLAGS = -fPIC -Iinclude -I $(HOME)/.asdf/installs/erlang/26.2.1/erts-14.2.1/include -lgmp -lcrypto -o ../native_lib/mac/$(ARCH)/liboqs.so liboqs.c ../native_lib/mac/$(ARCH)/liboqs.a -bundle -bundle_loader $(HOME)/.asdf/installs/erlang/26.2.1/erts-14.2.1/bin/beam.smp
endif


liboqs.so: liboqs.c
	gcc $(CFLAGS)

clean:
	rm *.so
