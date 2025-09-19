# Crypto
## Pedantic

>### HitconCTF 2025
>#### https://ctf2025.hitcon.org/dashboard/#1

Esse é o write-up do desafio Pedantic, do HitconCTF 2025.

## Instruções para instalar o SageMath e rodar o exploit

Para reproduzir o exploit, é conveniente usar o SageMath porque ele já traz campos finitos, matrizes e algoritmos de lattices prontos.

### Instalando o SageMath

- Ubuntu/Debian:  
  ```bash
  sudo apt-get update
  sudo apt-get install sagemath
  ```

- Arch Linux:  
  ```bash
  sudo pacman -S sagemath
  ```

- Conda (qualquer SO):  
  ```bash
  conda install -c conda-forge sagemath
  ```

### Rodando o exploit

Após instalar o SageMath, no mesmo diretório do `exploit.py`:

```bash
sage -python exploit.py
```

Assim o exploit é executado com o interpretador do SageMath (que já traz as dependências).

## Entendendo o desafio

O desafio Pedantic do HITCON CTF 2025 é um exemplo clássico de como um detalhe aparentemente inofensivo - um gerador linear - pode comprometer um sistema criptográfico inteiro.

O arquivo `server.py` implementa uma prova de conhecimento zero (Zero-Knowledge Proof, ZKP) sobre a curva elíptica secp256k1.
O servidor conhece um segredo (derivado da flag) e publica uma prova com 10 rodadas.
O jogador precisa enviar uma prova com `≥42` rodadas válidas para ganhar a flag, mas sem conhecer o segredo.

A vulnerabilidade está em como os desafios 
$c_i$ são gerados: um gerador linear congruencial (LCG), previsível, em vez de uma função criptográfica forte. Essa fraqueza permite que controlemos os desafios e forjemos uma prova.

## Conceitos teóricos

### Curvas Elípticas

Uma curva elíptica sobre um corpo finito é um conjunto de pontos que satisfaz uma equação como  

$$ y^2 = x^3 + ax + b \ mod \ p $$

Sobre esse conjunto existe uma operação de adição entre pontos e multiplicação escalar por inteiros.

No código `server.py` temos:

```python
p = secp256k1.p
q = secp256k1.q
G = secp256k1.G
```

Aqui:
- `p` é o módulo do campo.
- `q` é a ordem do ponto gerador `G`.
- `G` é o ponto gerador usado para multiplicar números e obter pontos na curva.

Quando temos um segredo x, podemos calcular a chave pública $Y = xG$. Esse é o mesmo mecanismo usado no Bitcoin.

### Provas de conhecimento zero no estilo Schnorr

A prova Schnorr é uma forma de provar que você conhece x tal que $Y=xG$ sem revelar x.

Ela funciona assim para cada rodada:
1. O provador escolhe r aleatório e envia $R=rG$.
2. O verificador envia um desafio c.
3. O provador responde $z=r+cx \ mod \ q$.
4. O verificador checa $Gz=R+Yc$.

Se essa equação vale, o verificador fica convencido de que você sabe x, sem ele mesmo saber o  valor de x.

No código, a geração de prova está em:

```python
def prove(x, n):
    rs = [secrets.randbelow(q) for _ in range(n)]
    Grs = [G * r for r in rs]
    cs = hash_points_to_scalars(Grs, n)
    zs = [(r + c * x) % q for r, c in zip(rs, cs)]
    return list(zip(Grs, zs))
```

### Fiat–Shamir: desafios sem interação

Como não há um verificador humano para enviar os desafios, usa-se a heurística de Fiat–Shamir: os desafios são derivados de um hash dos compromissos $R_i$. Se o hash for seguro e imprevisível, não conseguimos manipular $c_i$. Mas aqui foi usado um gerador linear previsível.

No servidor

```python
cs = hash_points_to_scalars(Grs, n)
```

gera os desafios a partir dos compromissos.

### Gerador linear congruencial (LCG)

Um LCG é um gerador de números pseudoaleatórios da forma

$$s_{n+1} = (a s_n + b) \ mod \ q$$

Ele é determinístico e linear. Se conhecemos a e b, conseguimos prever toda a sequência. Mais ainda: existe um ponto fixo c satisfazendo

$$c = a c + b \ (mod \ q)$$

ou seja

$$c=-b/(a-1) \ (mod \ q)$$

Se o LCG começar em c, todos os valores seguintes serão iguais.

No código:

```python
  s = sum([hash_point(pt) for pt in pts]) % q
  ret = []
  for _ in range(n):
      ret.append(s)
      s = (1337 * s + 7331) % q
```

Temos $a=1337$ e $b=7331$.

## Como deveria ser seguro e por que não é

A segurança do Schnorr/FIAT–Shamir depende dos desafios $c_i$ serem imprevisíveis. Se conseguirmos fixá-los ou escolhê-los, podemos forjar provas sem saber o segredo x.

No `server.py`, `hash_points_to_scalars` recebe pontos controláveis (os compromissos enviados pelo atacante) e deriva a semente do LCG como a soma dos hashes desses pontos. Portanto podemos manipular essa semente inicial. E como o LCG é linear e tem ponto fixo, podemos escolher a semente para fazer todos os $c_i$ iguais.

## Explorando a vulnerabilidade

### Recuperando a chave pública Y
O servidor não mostra Y diretamente, mas fornece 10 rodadas da prova. Sabendo que:

$$Gz_i = R_i + Yc_i => Y=(Gz_i-R_i)c_i^{-1} \ mod \ q$$

podemos recomputar $c_i$ e achar Y.

No `exploit.py`:

```python
cs = hash_points_to_scalars(Grs, len(Grs))
Y = (G * zs[0] - Grs[0]) * pow(cs[0], -1, q)
```

### Fixando os desafios
Calculamos o ponto fixo do LCG:

```python
a=1337; b=7331
c = int(-b / (a-1))
```

Se fizermos a soma dos hashes = c, então $c_i=c$ para todas as rodadas.

### Construindo compromissos falsos
Escolhemos $z_i$ arbitrários e fazemos:

$$R_i = G z_i - Y c$$

Isso garante que 

$$Gz_i=R_i+Yc$$

No exploit:

```python
zs = list(range(m))
Grs = [G * z - Y * c for z in zs]
```

### Ajustando a soma dos hashes
Precisamos de inteiros  $t_i$ tais que:

$$∑t_ih_i=c \ (mod \ q)$$

onde 

$$h_i=hash(R_i)$$

Se encontrarmos $t_i$ não negativos, podemos repetir cada ($R_i$ , $z_i$) $t_i$ vezes, construindo uma prova gigante.

Esse é um problema clássico de lattices:

* Cada $h_i$ é uma “direção” no lattice.
* Queremos uma combinação inteira que chegue a c.

## Conceitos avançados: lattices, LLL e CVP

Um lattice é um conjunto de pontos em $R^n$ gerado por combinações lineares inteiras de vetores base. Encontrar combinações inteiras que satisfazem restrições modulares é muitas vezes equivalente a resolver um problema em um lattice.

O algoritmo LLL reduz uma base de lattice para uma forma “mais curta” que facilita encontrar soluções inteiras pequenas. O Closest Vector Problem (CVP) tenta achar o ponto do lattice mais próximo de um vetor dado.

No exploit, usamos LLL + CVP para achar coeficientes $t_i$ inteiros pequenos que satisfazem a soma de hashes = c, ou seja,

$$∑t_ih_i=c$$

É isso que permite inflar a prova para mais de 42 rodadas.


## O exploit passo a passo

### Recebendo a prova inicial e extraindo Y

```python
proof = deserialize_proof(io.recvlineS().strip())
Grs, zs = zip(*proof)
cs = hash_points_to_scalars(Grs, len(Grs))
Y = (G * zs[0] - Grs[0]) * pow(cs[0], -1, q)
```

### Calculando o ponto fixo c

```python
F = GF(q)
a = F(1337)
b = F(7331)
c = int(-b / (a - 1))
```

### Criando candidatos $z_i$ e $R_i$

```python
m = 80
zs = list(range(m))
Grs = [G * z - Y * c for z in zs]
hs = [hash_point(Gr) for Gr in Grs]
```

### Montando o sistema e resolvendo com `lll_cvp.py`

```python
L = matrix(F, hs)
rhs = vector(F, [c])
s0 = L.solve_right(rhs).change_ring(ZZ)
ker = L.right_kernel_matrix()
t = affine_cvp(s0, qary_lattice(ker, q), vector([20] * m))
```

### Construindo a prova gigante

```python
Grs = sum([[Gr] * x for Gr, x in zip(Grs, t)], [])
zs = sum([[z] * x for z, x in zip(zs, t)], [])
proof = list(zip(Grs, zs))
```

### Enviando a prova ao servidor

```python
io.sendline(serialize_proof(proof).encode())
```

O servidor roda `verify(Y,proof)`, encontra `≥42` rodadas válidas e revela a flag.

## Lições aprendidas

- Desafios devem ser imprevisíveis: Não use PRNG fraco ou linear para derivá-los.
- Entradas controláveis devem ter salt: Somar hashes direto sem salt pode permitir manipulação.
- Provas de conhecimento zero são tão seguras quanto seu mecanismo de desafios.
- lattices: são ferramentas poderosas para resolver problemas modulares quando há espaço para manipulação.

Este desafio mostra, passo a passo, como uma implementação frágil do Fiat–Shamir (LCG + hash direto) permite que um atacante, usando álgebra em curvas e técnicas de lattices, crie uma prova falsa com `≥42` rodadas sem conhecer o segredo e assim capture a flag.
