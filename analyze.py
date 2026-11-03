from pathlib import Path
import re

from perfis import regra_fora_perfil_ping_local

EVIDENCE = Path(__file__).resolve().parent / "evidence"

texto = r'"(?:\\.|[^"\\])*"'
argumentos = rf'\[(?:{texto}(?:,\s*{texto})*)?\]'

padrao = re.compile(
    r'^execve\("(?P<executavel>(?:\\.|[^"\\])*)",\s*'
    rf'(?P<argumentos>{argumentos}),\s*'
    r'.*\)\s*=\s*(?P<resultado>.+)$'
)

def ler_coleta(caminho):
    eventos = []
    pendencias = []
    marcadores = (
        " execve(",
        " execveat(",
        "<... execve resumed>",
        "<... execveat resumed>",
    )

    with caminho.open(encoding="utf-8") as arquivo:
        for numero, linha in enumerate(arquivo, start=1):
            if not any(marcador in linha for marcador in marcadores):
                continue

            origem = f"{caminho.name}:{numero}"
            partes = linha.split(maxsplit=2)

            if len(partes) != 3:
                pendencias.append(f"{origem}: {linha.rstrip()}")
                continue

            pid, horario, chamada = partes
            m = padrao.match(chamada)
            if m is None:
                pendencias.append(f"{origem}: {linha.rstrip()}")
                continue

            evento = m.groupdict()
            evento.update(origem=origem, pid=pid, horario=horario)
            eventos.append(evento)

    return eventos, pendencias

def regra_shell(evento, _referencia):
    return evento["executavel"] == "/bin/sh"


def regra_fora_referencia(evento, referencia):
    return evento["executavel"] not in referencia


def regra_argumentos_novos(evento, referencia):
    executavel = evento["executavel"]
    return (
        executavel in referencia
        and evento["argumentos"] not in referencia[executavel]
    )

REGRAS = {
    "shell_bin_sh": regra_shell,
    "fora_referencia": regra_fora_referencia,
    "argumentos_novos": regra_argumentos_novos,
    "fora_perfil_ping_local": regra_fora_perfil_ping_local,
}

def analisar_regras():
    nomes = (
        "baseline-ping.strace",
        "command-injection-whoami.strace",
        "legitimate-ping-127-0-0-2.strace",
        "command-injection-printf.strace",
    )
    coletas = [(nome, *ler_coleta(EVIDENCE / nome)) for nome in nomes]
    _, eventos_base, pendencias_base = coletas[0]

    if pendencias_base or not eventos_base:
        for pendencia in pendencias_base:
            print(f"Não interpretado: {pendencia}")
        raise SystemExit("Referência vazia ou incompleta. Análise interrompida.")

    referencia = {}
    for evento in eventos_base:
        referencia.setdefault(evento["executavel"], set()).add(evento["argumentos"])

    print("Referência:", ", ".join(sorted(referencia)))

    for nome, eventos, pendencias in coletas:
        contagens = dict.fromkeys(REGRAS, 0)
        print(f"\nCOLETA: {nome}")

        for evento in eventos:
            sinais = []
            for nome_regra, regra in REGRAS.items():
                if regra(evento, referencia):
                    sinais.append(nome_regra)
                    contagens[nome_regra] += 1

            print(
                f"\n{evento['origem']} | PID {evento['pid']} | "
                f"Unix {evento['horario']}"
            )
            print(f"{evento['executavel']} {evento['argumentos']}")
            print(f"execve: {evento['resultado']}")
            print("Revisar:", ", ".join(sinais) or "nenhuma regra")

        for pendencia in pendencias:
            print(f"Não interpretado: {pendencia}")

        resumo = ", ".join(f"{k}={v}" for k, v in contagens.items())
        print(f"\nRESUMO: {nome} | eventos={len(eventos)} "
              f"| não interpretadas={len(pendencias)} | {resumo}")

# Campos: título, coleta antes, coleta depois, repetições antes/depois, log depois.
CENARIOS = (
    (
        "Ping legítimo: 127.0.0.1",
        "baseline-ping.strace",
        "fixed-legitimate-ping-127-0-0-1.strace",
        (4, 1),
        None,
    ),
    (
        "Adição de whoami",
        "command-injection-whoami.strace",
        "fixed-command-injection-whoami.strace",
        (1, 2),
        "fixed-command-injection-whoami.container.log",
    ),
    (
        "Ping legítimo: 127.0.0.2",
        "legitimate-ping-127-0-0-2.strace",
        None,
        (1, None),
        None,
    ),
    (
        "Adição de printf",
        "command-injection-printf.strace",
        "fixed-command-injection-printf.strace",
        (2, 2),
        "fixed-command-injection-printf.container.log",
    ),
)

MARCADOR = "PURPLECHECK event=ping_input_rejected"
PADRAO_REJEICAO = re.compile(
    r"^(?P<horario>\S+)\s+"
    r"\[[^\]]+\]\s+\[php:notice\]\s+"
    r"\[pid [^\]]+\]\s+\[client [^\]]+\]\s+"
    r"PURPLECHECK event=ping_input_rejected reason=invalid_ipv4"
    r"(?:,\s+referer:.*)?$"
)

def ler_rejeicoes(caminho):
    registros = []
    pendencias = []

    with caminho.open("r", encoding="utf-8") as arquivo:
        for numero, linha in enumerate(arquivo, start=1):
            if MARCADOR not in linha:
                continue

            origem = f"{caminho.name}:{numero}"
            m = PADRAO_REJEICAO.fullmatch(linha.rstrip("\r\n"))

            if m is None:
                pendencias.append(f"{origem}: {linha.rstrip()}")
                continue

            registros.append({
                "origem": origem,
                "horario": m["horario"],
            })

    return registros, pendencias

def mostrar_coleta(nome):
    if nome is None:
        print("Coleta após a correção: não realizada.")
        return 0

    caminho = EVIDENCE / nome
    eventos, pendencias = ler_coleta(caminho)

    print(f"Arquivo: {nome}")
    print(f"Tamanho: {caminho.stat().st_size} bytes")
    print(f"Chamadas de execução interpretadas: {len(eventos)}")
    print(f"Linhas selecionadas não interpretadas: {len(pendencias)}")

    for evento in eventos:
        print(
            f"  {evento['origem']} | {evento['executavel']} | "
            f"argumentos={evento['argumentos']} | "
            f"retorno={evento['resultado']}"
        )

    for pendencia in pendencias:
        print(f"  Não interpretado: {pendencia}")

    return len(pendencias)

def mostrar_rejeicoes(nome):
    if nome is None:
        print("Log de rejeições após a correção: não incluído neste caso.")
        return 0

    registros, pendencias = ler_rejeicoes(EVIDENCE / nome)

    print(f"Log da aplicação: {nome}")
    print(f"Registros de rejeição interpretados: {len(registros)}")
    print(f"Linhas com marcador não interpretadas: {len(pendencias)}")

    for registro in registros:
        print(f"  {registro['origem']} | horário={registro['horario']}")

    for pendencia in pendencias:
        print(f"  Não interpretado: {pendencia}")

    return len(pendencias)

def verificar_arquivos():
    for _, antes, depois, _, log in CENARIOS:
        for nome in (antes, depois, log):
            if nome is not None and not (EVIDENCE / nome).is_file():
                raise FileNotFoundError(
                    f"Evidência esperada não encontrada: {EVIDENCE / nome}"
                )

def comparar_correcao():
    print("COMPARAÇÃO ANTES E DEPOIS DA CORREÇÃO")
    pendencias = 0

    for titulo, antes, depois, (rep_antes, rep_depois), log in CENARIOS:
        print(f"\nCENÁRIO: {titulo}")
        print(f"Repetições anotadas antes: {rep_antes}")
        print(
            "Repetições anotadas depois:",
            rep_depois if rep_depois is not None else "não realizado",
        )

        print("\nANTES")
        pendencias += mostrar_coleta(antes)
        print("\nDEPOIS")
        pendencias += mostrar_coleta(depois)
        pendencias += mostrar_rejeicoes(log)

    print(f"\nTotal de linhas selecionadas não interpretadas: {pendencias}")
    print("Contagens não são métricas de eficácia; coleta vazia não comprova bloqueio.")

    return 1 if pendencias else 0

def main():
    verificar_arquivos()
    analisar_regras()
    print()
    return comparar_correcao()

if __name__ == "__main__":
    raise SystemExit(main())
