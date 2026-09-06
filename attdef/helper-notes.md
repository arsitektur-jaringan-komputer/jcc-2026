- run.py & checker.py jgn diganti, copas dr folder example (Dockerfile & requirements.txt harusny ga juga)
- probset cm bikin src/ poc/ challenge.yml & checker/checks.py
- inside src/, selain chall, probset bikin 2 files:

1. Dockerfile: run chall nya, tp directive terakhir SAMA: `CMD ["supervisord", "-c", "/etc/supervisord.conf"]`
2. supervisord.conf HANYA di blok [program:x]. bisa lebih dari satu, tp blok-blok di atasnya ga usah disentuh. biasanya directive command= di [program:svc] aja yg diganti, tp klo butuh process lain (e.g., php-fpm, nginx, db, dll), tambahin [program:y] sebanyak process yg diperlukan. tujuannya biar klo service mati, container ga fail/down. di-autorestart & dipantau atmin (supervisord)
