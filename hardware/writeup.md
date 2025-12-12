# Hardware

## Flagrom

> ### Google CTF 2019
> https://github.com/google/google-ctf/tree/main/2019/quals/hardware-flagrom

## 1. Introdução

Este writeup descreve a exploração de uma falha lógica no SecureEEPROM, um módulo de memória implementado em SystemVerilog e conectado a um microcontrolador Intel 8051 via barramento I2C.

O desafio simula um firmware legítimo que:
- Grava a flag na EEPROM (banco 1, bytes 64–127);
- Ativa um mecanismo de “secure bank”;
- Apaga a cópia do flag da RAM;
- Permite então a execução de código fornecido pelo usuário.

A expectativa é que, com o banco “seguro”, a leitura não seja possível.
Mas uma falha na implementação do hardware permite leitura fora de escopo, contornando totalmente a proteção.

## 2. Arquitetura geral do ambiente

### 2.1 O microcontrolador Intel 8051

O 8051 é um microcontrolador clássico, usado por décadas em sistemas embarcados.

Ele possui dois espaços de memória relevantes para o desafio:

#### SFR – Special Function Registers

Regiões mapeadas em endereço fixo que controlam periféricos.
Exemplos no desafio:

| Endereço	|       Função          |
| ---       |       ---             |
| 0xFA		| RAW_I2C_SCL (GPIO)    |
| 0xFB		| RAW_I2C_SDA (GPIO)    |
| 0xFC		| I2C_STATE             |
| 0xFD		| CHAROUT               |
| 0xFE		| DEBUG                 |
| 0xFF		| POWEROFF              |

#### XDATA

Memória RAM externa.
Usada para buffers e parâmetros do módulo I2C interno.

No firmware, o módulo I2C interno usa o endereço `0xFE00–0xFE0F`.

### 2.2 O barramento I2C – visão rápida e relevante

O I2C é composto por duas linhas:

* SCL – clock
* SDA – dados

Operações básicas:
- START
- SDA ↓ enquanto SCL ↑
- STOP
- SDA ↑ enquanto SCL ↑
- ACK / NACK

O receptor controla SDA na subida de SCL:
- 0 = ACK
- 1 = NACK

Cada byte é transmitido bit a bit no pulso do clock.

### 2.3 Bit-banging: acesso direto às linhas I2C

O aspecto mais importante desse desafio é que o atacante recebe:

```
RAW_I2C_SCL => SFR 0xFA  
RAW_I2C_SDA => SFR 0xFB
```

Ou seja, além do módulo I2C normal, o usuário pode simular manualmente o protocolo I2C bit a bit, controlando diretamente as linhas físicas.

Isto torna possível enviar STARTs e comandos não previstos pelo firmware, algo equivalente a ter acesso físico ao barramento.

### 2.4 O SecureEEPROM (SystemVerilog)

O chip possui:
- 256 bytes de memória
- Divididos em 4 bancos de 64 bytes
- Cada banco pode ser marcado como seguro via um bitmask de 4 bits:

`logic [3:0] mem_secure;`

Quando seguro, esse banco não deve ser lido via I2C.

## 3. A camada de firmware legítimo

O firmware faz o seguinte:
1) Escreve a flag no banco 1 (offset 64)
2) Chama seeprom_secure_banks(0b0010) => marca o banco 1 como seguro
3) Apaga a flag da memória RAM
4) Permite a execução do usercode

Ele usa apenas o módulo I2C interno, que automaticamente emite um STOP ao finalizar operações.
Esse detalhe será crucial para a exploração.

## 4. A lógica de segurança do SecureEEPROM

A lógica relevante do SystemVerilog é:

### 4.1 Verificação de endereço seguro ao carregar o endereço:

```
if (i2c_address_secure) begin
    i2c_address_valid <= 0;
    i2c_state <= I2C_NACK;
end else begin
    i2c_address_valid <= 1;
    i2c_state <= I2C_ACK_THEN_WRITE;
end
```

Ou seja, se você tentar apontar o endereço dentro de um banco seguro, a operação é invalidada.

### 4.2 Verificação durante leituras contínuas (vulnerável)

Ao ler bytes sequenciais, o chip compara de forma errada:

```
if (i2c_address_secure == i2c_next_address_secure) begin
    read/write OK
end else begin
    NACK
end
```

Grave problema: ele não verifica se a área é segura.
Apenas se ambas são seguras ou ambas são inseguras.

Isso cria o cenário crítico:

| Endereço atual		|			Próximo		|	Ambos seguros?	|	Permite leitura? |
| --- | --- | --- | --- |
| 63 (bank 0)		|			64 (bank 1)	|	?	|		Aqui deveria bloquear |
| 63 (bank 0 marcado como seguro manualmente) |	64 (flag, seguro) |	sim	|		BUG: libera leitura da área protegida! |

Eis a vulnerabilidade central.

## 5. Controle de estado I2C - como o ataque funciona

O módulo I2C interno sempre envia STOP, o que força:

```
i2c_address_valid = 0
state = IDLE
```

Isso impede qualquer exploração usando o módulo normal.

Mas usando bit-bang via RAW_I2C_SCL/SDA, o usuário pode:
- Gerar STARTs repetidos
- Nunca emitir STOP
- Manter i2c_address_valid = 1
- Manipular o estado da FSM do SecureEEPROM de forma não prevista

Na especificação oficial do I2C, um Repeated START é válido e não reinicia a comunicação.

## 6. A vulnerabilidade explorada (resumo conceitual)

A exploração ocorre combinando três falhas de design:

### Falha 1 - Verificação incorreta de segurança entre endereços

O chip não verifica se o endereço é seguro, apenas se A e B têm o mesmo status.

Se o atacante marcar dois bancos como “seguros”, a leitura entre eles não será bloqueada.

Isso inclui o banco do flag.

### Falha 2 - `i2c_address_valid` pode ser mantido em 1

O valor que habilita a leitura não é resetado enquanto:
- Não for enviado STOP
- Não for selecionado um endereço seguro

Mas o atacante evita STOP (bit-banging) e usa apenas endereços não seguros no início.

### Falha 3 - START repetido altera o estado sem resetar flags

Repeated START força a FSM a continuar a operação, permitindo:
- Redefinir endereço de controle
- Mudar o modo para leitura ou secure
- Sem invalidar a operação anterior

## 7. Sequência do ataque

### Passo 1 - Escolher um endereço válido

Enviar:

```
start
control = SEEPROM_I2C_ADDR_MEMORY (modo write)
address = 63
```

63 fica em bank 0, não seguro, portanto:

`i2c_address_valid = 1`

### Passo 2 - Marcar o banco 0 como seguro

```
start
control = SEEPROM_I2C_ADDR_SECURE | 0b0001
```

### Passo 3 - Ler iniciando pelo bank 1

```
start
control = SEEPROM_I2C_ADDR_MEMORY | 1 (modo read)
```

Por que funciona?

Porque no estado:

```
endereço atual = 63 (bank 0, seguro)
próximo endereço = 64 (bank 1, seguro)
```

O chip avalia:

`secure(63) == secure(64) => verdadeiro`

E permite leitura contínua.

Isso vaza todos os 64 bytes do banco 1, incluindo o flag.

## 8. Conclusão da análise

O erro de implementação consiste em:

### O chip não verifica se um endereço é seguro:

Ele só compara igualdade entre os níveis de segurança de dois bancos.

### Falha adicional: Repeated START permite manipular FSM

Evitando STOP, o atacante mantém a máquina de estados em um ponto vantajoso.

### Exposição desnecessária de GPIO de I2C

Acesso direto às linhas SDA/SCL é equivalente a acesso físico - basta seguir o protocolo manualmente.

Resultado: total bypass da proteção. A proteção de banco seguro é completamente anulada.

## 9. Impacto real

Este tipo de falha é relevante em:
- HSMs simplificados
- EEPROMs usadas em secure-boot
- Microcontroladores que confiam em FSMs para segurança
- Chips que implementam “proteção por banco” (muito comum em cartões IC)

Se um atacante obtiver acesso às linhas I2C ou SPI, falhas similares podem levar a exfiltração de chaves, firmware, flags, etc.