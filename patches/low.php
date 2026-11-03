<?php

if (isset($_POST['Submit'])) {
    $target = $_POST['ip'] ?? '';

    if (
        !is_string($target) ||
        filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false
    ) {
        error_log('PURPLECHECK event=ping_input_rejected reason=invalid_ipv4');
        $html .= '<pre>Entrada rejeitada: informe um IPv4 válido.</pre>';
        return;
    }

    $buffer = tmpfile();
    $command = ['/usr/bin/ping', '-n', '-c', '4', '-w', '5', $target];
    $descriptors = [
        0 => ['file', '/dev/null', 'r'],
        1 => $buffer,
        2 => $buffer,
    ];

    $pipes = [];
    $process = proc_open($command, $descriptors, $pipes);

    if (!is_resource($process)) {
        fclose($buffer);
        $html .= '<pre>Erro ao rodar o ping.</pre>';
        return;
    }

    $exitCode = proc_close($process);

    rewind($buffer);
    $output = stream_get_contents($buffer);
    fclose($buffer);

    $html .= '<pre>' . htmlspecialchars($output, ENT_QUOTES, 'UTF-8') . '</pre>';

    if ($exitCode !== 0) {
        $html .= '<pre>Ping encerrado com código ' . $exitCode . '.</pre>';
    }
}
