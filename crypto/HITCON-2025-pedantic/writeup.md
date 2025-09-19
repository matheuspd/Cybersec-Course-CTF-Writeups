# Crypto
## Pedantic

---

>#### HitconCTF 2025
>##### https://ctf2025.hitcon.org/dashboard/#1

Esse é o write-up do desafio Pedantic, do HitconCTF 2025.

## Entendendo o desafio
 O objetivo do desafio consiste em provar ao servidor que conhecemos a chave secreta (hash da flag) para uma chave pública usando uma prova ZKP (zero knowledge proof) da curva elíptica secp256k1.

 O ZKP é multi-rodadas, e o fiat-shamir faz hash de pontos válidos em q e os soma para formar uma semente. A semente é usada como entrada para um LCG (Linear Congruential Generator) para gerar os challenges para cada rodada. O objetivo é forjar uma prova contendo mais de 42 rodadas.

 Primeiramente, o desafio não fornece a chave pública diretamente, mas podemos usar a prova de 10 rodadas fornecida para calculá-la. Usamos a prova para calcular os challenges ci para cada rodada, então a chave pública é:
 ````
Y = ci^(-1)(Gzi - (Gri)).
 ````

 Para forjar uma prova com as 42 rodadas que precisamos, podemos explorar uma vulnerabilidade na função _hash_points_to_scalars_.

 Depois da soma s ser calculada, ela é usada como semente de um LCG para gerar os challenges. Como LCGs têm um ponto fixo c = -b(a-1)^(-1) onde ``ac + b = c``, se definirmos ``s = c`` então todos os desafios ci serão iguais a c.

 E nós podemos gerar pontos Gr em que a soma dos seus hashes é c. Basta gerarmos alguns zs e calcular os valores correspondentes de Grs, dado por:
 ````
 Gri = G * zi - Y * ci
 ````
 Em seguida salvamos seus hashes numa lista hs. Daí podemos usar o algoritimo LLL para descobrir um conjunto solução pequeno de Ai inteiros em hs que sua soma resulte em c.

 Para cada iteração, o valor de zi e Gri é duplicado Ai vezes, então uma prova de Ai rodadas é gerada. Como todos os cs na verificação são iguais, a prova é válida.