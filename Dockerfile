FROM --platform=linux/x86_64 ubuntu:22.04

RUN apt-get update && apt-get install -y git curl astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind libgmp3-dev exuberant-ctags

RUN apt-get install -y libncurses-dev

SHELL ["/bin/bash", "--login", "-c"]
RUN git clone https://github.com/asdf-vm/asdf.git $HOME/.asdf --branch v0.14.0 && \
  echo ". $HOME/.asdf/asdf.sh" >> ~/.bashrc && \
  echo ". $HOME/.asdf/asdf.sh" >> ~/.zshrc

RUN . $HOME/.asdf/asdf.sh && asdf plugin add erlang && \
  asdf plugin add elixir && \
  asdf install erlang 26.2.1 && \
  asdf install elixir 1.15.7-otp-26 && \
  asdf global erlang 26.2.1 && \
  asdf global elixir 1.15.7-otp-26

WORKDIR /opt

CMD ["/bin/bash"]
