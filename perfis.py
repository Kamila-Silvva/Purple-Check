import re
from ipaddress import IPv4Address

PING = {
    "/bin/sh": r'\["sh",\s*"-c",\s*"--",\s*"ping\s+-c\s+4\s+([0-9.]+)"\]',
    "/usr/bin/ping": r'\["ping",\s*"-c",\s*"4",\s*"([0-9.]+)"\]',
}

def regra_fora_perfil_ping_local(evento, referencia):
    padrao = PING.get(evento["executavel"])
    if padrao is None:
        return True

    m = re.fullmatch(padrao, evento["argumentos"])
    if m is None:
        return True

    try:
        destino = IPv4Address(m.group(1))
    except ValueError:
        return True

    return not destino.is_loopback
