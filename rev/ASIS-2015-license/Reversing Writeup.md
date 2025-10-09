
Disas da main:
![dissasembly da função main](./images/main.png)

Escreve o nome "*a\nb\tc*" no rdi -> posteriormente usado como parâmetro da função fopen

```bash
hexdump -ve '1/1 "%.2X"' license | sed 's/5F610A6209635F/4d415449415321/g' | xxd -r -p > license_novo
```

Agora criamos um arquivo chamado 'MATIAS!'

e temos o erro: 
```
wrong formated key file
```
e não:
```
key file not found!
```
![[Pasted image 20251009175257.png]]


![[Pasted image 20251009175211.png]]

![[Pasted image 20251009181257.png]]

descobrimos assim que o número de caracteres em cada uma das linhas deve ser 6

${{34 - (5 - 1) }\over 5} = 6$

