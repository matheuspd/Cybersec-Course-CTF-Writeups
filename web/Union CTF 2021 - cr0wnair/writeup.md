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
Porém a na linha 42 de checkin.js existe a verificação data["extras"][e]["sssr"] == "FQTU"
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
