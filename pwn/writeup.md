# Writeup secret notes (HITCON CTF 2025)

## 1) Resumo

O binário mantém estado de parsing com `strtok` em buffers que podem ser `free()`d. Combinando esse *use-after-free* lógico com um caminho de código que faz `strdup`/`malloc` retornar `NULL` (forçando o parser a continuar a partir do ponteiro interno do `strtok`) e manipulando metadados do `tcache`, o atacante consegue induzir o parser a interpretar bytes controlados pelo `malloc` (tcache key + conteúdo de chunk) como um cabeçalho de nota válido. Isso leva a um write fora de limites (OOB), corrompe metadados de heap, permite vazamento de heap e libc e, finalmente, tcache poisoning para escrever um *fake FILE* em `_IO_2_1_stderr_` e executar `system("/bin/sh")` (RCE).

## 2) Vulnerabilidade(s) central(is) - descrição técnica

1. **Dependência do estado interno do `strtok`**: `strtok` armazena em estado interno um ponteiro para a última string processada. Quando chamadas subsequentes usam `strtok(NULL, ... )` esse ponteiro é reutilizado. O código do desafio assume que esse ponteiro sempre apontará para uma string válida criada no ciclo de vida da nota - mas se a nota for `free()`d, o ponteiro passa a apontar para memória liberada.

2. **`strtok` não copia a string**: a função `strtok` altera o buffer original (coloca `\0` nos delimitadores) e retorna ponteiros para dentro desse buffer. Se essa memória é liberada e depois reutilizada pelo allocator, o conteúdo pode ser sobrescrito por metadata de `free`/`tcache`.

3. **Caminho de erro quando `strdup`/`malloc` falha**: é possível forçar um caminho de código onde a recepção de uma nota muito grande resulta em `strdup` retornando `NULL`. Em tal cenário, o código que deveria atualizar o ponteiro interno do `strtok` com um novo buffer acaba não fazendo isso, levando `strtok` a tentar parsear a memória apontada pelo ponteiro interno previamente salvo - que agora pode ter sido sobrescrita por metadata do malloc.

4. **Escrita de metadados do tcache**: quando um chunk é devolvido ao tcache, glibc escreve dados (forward pointer / chave) nos primeiros bytes do chunk livre. Isso significa que `free` pode escrever inteiros controláveis (dependendo do estado do tcache) dentro do espaço que `strtok` pode vir a ler.

5. **Consequência prática**: unindo os pontos acima, o parser pode aceitar um "fake header" criado pela combinação do tcache key + bytes adjacentes como se fosse uma nova nota (com *small key*), o que produz um comportamento de escrita fora do domínio esperado (OOB) e abre caminho para manipulação de metadados do heap.

## 3) Conceitos teóricos envolvidos

### `strtok` e estado interno

- `strtok` separa tokens modificando diretamente a string de entrada e mantendo um ponteiro estático para a próxima posição. Em código multithread ou quando a string original tem ciclo de vida curto, usar `strtok` é perigoso; prefira `strtok_r` com cópias explícitas dos tokens caso a string original seja volatile.

- Importante: `strtok` não aloca, nem faz cópia. O ponteiro retornado refere-se ao próprio buffer.

### `strdup` / `malloc` e caminhos de erro

- Quando `malloc`/`strdup` retornam `NULL`, o programa deve tratar esse erro corretamente. Fluxos que ignoram o `NULL` e continuam processando estado antigo podem acionar UAF lógico ou usar ponteiros que deveriam ter sido substituídos.

### tcache (glibc)

- tcache é um fast-path de alocação que armazena listas singly-linked de chunks por tamanho. Ao dar `free()` um chunk, glibc escreve o ponteiro para o próximo elemento (forward pointer) no início desse chunk - portanto, o conteúdo do chunk muda durante o free.

- Exploits costumam usar essa escrita previsível para colocar valores controlados em memória conhecida (tcache poisoning), ou para fazer o programa interpretar esses bytes controlados como campos significativos.

### FILE structures e FSOP

- O *File Structure Oriented Programming* (FSOP) explora a possibilidade de corromper estruturas internas de `FILE` (como `_IO_FILE_plus`) para redirecionar execuções de funções via vtable. Em glibc, se você conseguir colocar um fake FILE em `_IO_2_1_stderr_` (ou similar) com campos e vtable controlados, operações de flush/escrita podem invocar `system`.

## 4) Estratégia de exploração - primitives e encadeamento

A exploração se divide em fases bem definidas:

1. **Preparar heap/layout**: alocar uma sequência de notas com tamanhos controlados para obter um layout previsível (stashes e victims).

2. **Preparar `strtok` para apontar para memória free’d**: criar uma nota cujo parsing deixará o ponteiro interno do `strtok` apontando para um offset dentro do chunk; em seguida deletar essa nota (UAF lógico do pointer de strtok).

3. **Forçar caminho de erro (big note)**: alocar notas enormes para causar `strdup(NULL)`/`malloc(NULL)` e forçar o código a reusar o ponteiro interno do `strtok` (que aponta para a memória freed).

4. **Fazer com que o tcache escreva uma chave sobre o byte de terminação da string**: liberar chunks no ponto certo para que glibc escreva o tcache forward pointer sobre o `\0` que o ponteiro de `strtok` esperava - assim o parser verá bytes diferentes (tcache key + bytes adjacentes) como novo header.

5. **Conseguir um small-key → OOB write**: o parser aceitará um key de tamanho pequeno (ex.: < 8) e o código do binário terá um comportamento que permite atingiar uma escrita OOB (estouro/controlada).

6. **Corromper tamanho do próximo chunk → overlap**: usar OOB para corromper metadados de size do próximo chunk, levando a um overlap entre um chunk de tcache e um chunk do unsorted bin.

7. **Vazar heap & libc**: ler através do chunk overlapped para obter um leak do heap (com cálculo específico para decodificar) e do libc (unsorted bin pointers).

8. **Tcache poisoning**: com `libc_base` conhecido, montar entradas de tcache para escrever onde quisermos - o objetivo é colocar um fake FILE em `_IO_2_1_stderr_ - 0x10` (ou similar).

9. **Construir payload FILE e disparar FSOP**: montar `FILE` estruturado para que a vtable aponte para `_IO_wfile_jumps` com um `chain` apontando para `system`, então acionar a operação que fará o glibc chamar a vtable e executar `system("/bin/sh")`.

## 5) Mapeamento do exploit (trechos comentados)

### 5.1 Login e xor key

- O exploit define a `key` que é usada pelo binário para XOR-ing dos campos das notas. O exploit trabalha criando notas já ``xor``adas onde necessário para que, após o processo do binário, os bytes lidos sejam os esperados.

### 5.2 `big` notes - forçar `malloc/strdup` falhar

- Trecho (pseudocódigo):

```py
big = b"A:" + key + b":"
big = big.ljust(0x16fffff, b"C")
add_note(big)  # repetir algumas vezes
```

Explicação: alocações enormes que esgotam o espaço e provocam retorno `NULL` em caminhos de duplicação, fazendo o parser recorrer ao ponteiro interno do `strtok`.

### 5.3 Preparar `prep` e deletar para criar o ponteiro interno apontando para freed

- Trecho (pseudocódigo):

```py
prep = add_note(<nota que contém "X:Y:Z" xored>)
del_note(prep)
```

Explicação: ao deletar `prep`, o ponteiro interno do `strtok` ainda aponta para a área desse chunk - agora free’d - pronto para ser interpretado depois.

### 5.4 Liberação do stash → disponibilizar entradas de tcache

- Libera os `stash` para popular tcache com chunks de tamanho conhecido. Isso permite que, quando um chunk é freed, o forward pointer (tcache key) seja gravado nesses bytes controláveis.

### 5.5 Criar victim(s) e manipular frees para sobrescrever o terminador `\0`

- A combinação de `overwrite`, `victim1`, `victim2`, `padding`, `move` controla onde o tcache metadata vai cair e quais bytes serão vistos pelo `strtok` quando este for forçado a re-parsear o ponteiro interno. O objetivo é fazer com que o `\0` seja sobrescrito por parte do tcache forward pointer.

### 5.6 Obter leaks

- A leitura via `get_note(overlap)` seguida de `xor` e extração de offsets fornece primeiro um **heap leak** (transformado por `decrypt()` para reconstituir o heap base) e depois um **libc leak** (a partir de unsorted bin pointers na área overlapped).

### 5.7 Preparar e escrever o fake FILE

- Com `libc_base` conhecido e `heapbase` conhecido, o exploit monta um `note` que, após ser escrito no alvo, colocará uma estrutura `_IO_FILE_plus` em `_IO_2_1_stderr_` com campos:
  - `flags` contendo a string `sh` (ou outra forma de passar `/bin/sh`)
  - `_wide_data`, `_lock`, `chain` e `vtable` apontando para símbolos de libc e `system`

- Ao acionar a operação final de flush/escrita, o glibc usará o vtable corrompido chamando `system("/bin/sh")`.

## 6) Detalhes cruciais (offsets, tamanhos, transformações)

- **Tamanhos de alocação**: os tamanhos exatos (ex.: `0x10`, `0x106`, `0x216`, `0x3f6`, `0x446`) foram calibrados para a versão de glibc usada no desafio; pequenas variações tornam o exploit inválido.

- **XOR / encriptação**: o binário aplica XOR nos bytes do corpo da nota com uma `key` de 8 bytes. O exploit aplica a mesma operação em sentido reverso quando necessário.

- **Cálculo do heapbase**: a função `decrypt(heapleak)` transforma o leak (que vem cifrado/obfuscado pelo chall) para recuperar o endereço real do heap; o exploit então alinha por página (`heapbase = heapleak >> 12 << 12`).

- **Libc specific offsets**: o exploit subtrai um offset (`0x209b20` no exemplo) do `libcleak` para obter `libcbase` - esse valor depende da libc que acompanha o binário. Por isso o passo de copiar `libc.so.6` do container é crítico.

- **Target para FSOP**: `_IO_2_1_stderr_ - 0x10` é usado como alvo de escrita do fake FILE (o deslocamento exato pode variar por versão de libc).

## 7) Riscos, dependências e limitações

- O exploit é fortemente dependente da **versão da libc** e do **layout do heap**; transferir para outro ambiente requer recalibração.

- Transformações custom (por ex. a rotina `decrypt(heapleak)`) são específicas do desafio e não generalizam facilmente.

- Algumas etapas dependem de comportamento indefinido ou não-portável entre versões de glibc (por exemplo, onde exatamente o tcache escreve sua chave, ou offsets internos de `_IO_2_1_stderr_`).

## Preparação da resolução do desafio

- Instalar pwninit:

```bash
cargo install pwninit
# se der erro:
sudo apt install build-essential pkg-config liblzma-dev
```

- Rodar ambiente do desafio (exemplo):
```bash
docker compose up -d
# copiar libc do container:
docker cp pwn-secret-notes-1:/lib/libc.so.6 .
docker cp pwn-secret-notes-1:/lib64/ld-linux-x86-64.so.2 .
# instalar patchelf
sudo apt install patchelf
# patch e executar pwninit em src para gerar chal_patched
pwninit
# rodar exploit no docker
python3 solve.py LOCAL # ou python3 solve.py (roda no host local)
```
- Irá abrir um terminal do gdb, digite "continue".

- Irá abrir uma shell no terminal original.
