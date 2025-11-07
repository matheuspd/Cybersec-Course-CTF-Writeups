Baixar pwninit (https://github.com/io12/pwninit):
cargo install pwninit
(o meu deu erro, resolvi com: sudo apt install build-essential pkg-config liblzma-dev)

Rodar o docker:
docker compose up -d

Copiar as libs do docker (comandos no arquivo get_libc):
docker cp pwn-secret-notes-1:/lib/libc.so.6 .
docker cp pwn-secret-notes-1:/lib64/ld-linux-x86-64.so.2 .

Instale patchelf:
sudo apt install patchelf

Rode em src (irá gerar chal_patched):
pwninit

Rode o exploit (em um ambiente virtual de preferência):
python3 solve.py LOCAL (irá abrir shell dentro do docker)
ou
python3 solve.py

Irá abrir um terminal do gdb, digite "continue".
Irá abrir uma shell no terminal original, leia a flag no diretório anterior.
