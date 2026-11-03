# PurpleCheck

Projeto de estudo em Purple Team com Python, DVWA e strace.

Montei um laboratório para comparar o que aparece nos registros durante um ping legítimo e durante testes de command injection. O script lê essas coletas, aplica quatro regras e mostra as diferenças antes e depois de uma correção no PHP.

## O laboratório

Usei Kali Linux, DVWA e MariaDB em Docker, com a aplicação publicada em `127.0.0.1:4280`. Os testes foram feitos no exercício de command injection, no nível Low.

Os logs HTTP mostravam as requisições, mas não os programas executados. Para observar isso, acompanhei os processos Apache com `strace`, usando `-f -ttt -s 1024 -e trace=execve,execveat`.

| Entrada no formulário | Repetições antes da correção |
| --- | ---: |
| `127.0.0.1` | 4 |
| `127.0.0.2` | 1 |
| `127.0.0.1; whoami` | 1 |
| `127.0.0.1; printf PURPLECHECK_BUILTIN_OK` | 2 |

O `whoami` retornou `www-data` na página. O `printf` exibiu o marcador e foi identificado como um comando interno do shell nesse ambiente.

## O que o analisador faz

Cada evento mantém o arquivo e a linha de origem, PID, horário Unix, executável, argumentos e retorno de `execve`. A referência vem de `baseline-ping.strace`.

As regras são:

- `shell_bin_sh`: sinaliza a execução de `/bin/sh`.
- `fora_referencia`: sinaliza um caminho de executável que não apareceu na referência.
- `argumentos_novos`: sinaliza argumentos diferentes para um executável já conhecido.
- `fora_perfil_ping_local`: verifica os formatos de shell e ping definidos em `perfis.py`, com quatro pacotes e destino IPv4 de loopback.

O resultado é marcado como **revisar**. Um caminho ou argumento diferente pode ser legítimo.

## Resultados

Contagem de eventos sinalizados nas coletas anteriores à correção:

| Cenário | Shell | Caminho novo | Argumentos novos | Fora do perfil |
| --- | ---: | ---: | ---: | ---: |
| Ping `127.0.0.1` — 4 repetições | 4 | 0 | 0 | 0 |
| Ping `127.0.0.2` — 1 repetição | 1 | 0 | 2 | 0 |
| `whoami` — 1 repetição | 1 | 1 | 1 | 2 |
| `printf` — 2 repetições | 2 | 0 | 2 | 2 |

Um evento pode aparecer em mais de uma coluna.

O ping legítimo já abria um shell, então a primeira regra também sinalizou o uso normal. Comparar os argumentos literalmente trouxe outro problema: trocar apenas o IP para `127.0.0.2` gerou duas sinalizações.

No teste com `printf`, nenhum caminho novo apareceu. O comando foi executado dentro do shell, e a mudança ficou nos argumentos. Esse caso mostrou uma limitação da regra `fora_referencia`.

## Correção e reteste

O código original concatenava a entrada a uma chamada de `shell_exec`:

```php
$cmd = shell_exec( 'ping  -c 4 ' . $target );
```

Na correção, validei a entrada como IPv4 e passei o programa e seus argumentos em um array para `proc_open`:

```php
$command = ['/usr/bin/ping', '-n', '-c', '4', '-w', '5', $target];
$process = proc_open($command, $descriptors, $pipes);
```

Entradas inválidas recebem uma mensagem na página e o registro `PURPLECHECK event=ping_input_rejected reason=invalid_ipv4`. A validação aceita IPv4 válido; a restrição a loopback pertence à regra de detecção.

Depois da correção:

- **Ping `127.0.0.1`:** uma repetição, com execução de `/usr/bin/ping` e encerramento com código 0. Não houve execução de shell registrada.
- **`whoami` e `printf`:** duas tentativas de cada, rejeitadas na página, com dois registros de rejeição por cenário. Os arquivos de strace ficaram vazios.
- **Ping `127.0.0.2`:** não foi repetido.

As rejeições são registros da aplicação. A associação aos testes vem das anotações do laboratório, pois o marcador não contém a entrada enviada.

## Executar a análise

Com Python 3, `analyze.py`, `perfis.py` e a pasta `evidence/` no mesmo diretório:

```bash
python3 analyze.py
```

Não há dependências de pip. A análise usa os arquivos salvos e não precisa dos contêineres ligados. O comando mostra a comparação das regras e, em seguida, o relatório antes/depois.

Para salvar a saída (substitui o relatório se já existir):

```bash
mkdir -p reports
python3 analyze.py > reports/analise-completa.txt
```

| Arquivo ou pasta | Conteúdo |
| --- | --- |
| `analyze.py` | Leitura das evidências e os dois relatórios. |
| `perfis.py` | Perfil de ping local. |
| `evidence/` | Coletas, logs e registros do ambiente. |
| `patches/low.php` | Correção do exercício. |
| `compose.fixed.yml` | Imagem fixada por digest e montagem do PHP como somente leitura. |
| `reports/` | Saídas do analisador. |

A análise espera sete arquivos `.strace` e dois `.container.log`, nomeados em `CENARIOS`, no código. Os dois arquivos vazios após as rejeições também precisam estar presentes. O checkout do DVWA fica separado, em `../DVWA`.

## Escopo e pendências

Este é um estudo com quatro cenários. A mesma coleta usada para construir a referência também aparece na avaliação, e as repetições antes e depois são diferentes. As contagens não medem eficácia geral.

O parser interpreta linhas completas de `execve`. Chamadas selecionadas de `execveat`, retomadas ou truncadas ficam como pendências. Os argumentos são comparados como texto. A análise é retrospectiva, sem árvore de processos ou medição de tempo até alerta. Sucesso de `execve` não equivale a alerta, e uma coleta vazia, sozinha, não comprova bloqueio.

A versão atual de `low.php` foi simplificada depois das coletas, inclusive no tratamento de falhas, e passou por `php -l`. Falta repetir os testes com essa revisão e incluir o ping para `127.0.0.2` após a correção.

O commit do checkout, o digest e os dados dos contêineres estão nos arquivos de identificação em `evidence/`. O digest foi conferido na imagem usada; a correspondência entre a imagem e o commit do checkout não foi verificada.
