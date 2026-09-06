# JCC 2026

Collection of challenges for JCC 2026 competition

# Jeopardy

Inside `jeopardy` folder, the file structure for each challenges should look like this:

```
<name>/
├── release/
│   └── ...
├── source/
│   └── ...
└── poc/
    └── ...
└── challenge.yml
```

Explanation:

1. **\<name>** is the name of the challenge to be created.
2. **release** is the folder for the attachments to be given to the participants.
3. **source** is the folder used to store the original challenge source code, and if it’s a service, this folder will be deployed to the server. Please include `Dockerfile` or `docker-compose.yml`

> Why does the source folder need another \<name>?  
> To avoid conflicts in docker compose so they don’t sync with each other

1. **poc** is the folder that contains an explanation (or script) on how to solve each challenge (mandatory).
2. **challenge.yml** is used to specify each challenge. It contains the challenge title, author, description, category, type, and flag. For dynamic challenges, it also contains container information such as port to expose and flag format. Below are 2 kinds of `challenge.yml` that can be used, depending on your challenge type.

- For static, file-only challenges (where flag is **static**):

```yml
name: "<CHALLENGE_TITLE>"
author: "<YOUR_NAME>"
category: "<Crypto|Pwn|Web|Reverse|Forensics>"

description: |
  Lorem ipsum dolor sit amet.

type: "StaticAttachment"
flags:
  - "JCC{example_flag}"
provide: "./release"
```

- For dynamic challenges (where flag is **dynamic**):

```yml
name: "<CHALLENGE_TITLE>"
author: "<YOUR_NAME>"
category: "<Crypto|Pwn|Web|Reverse|Forensics>"

description: |
  Lorem ipsum dolor sit amet.

type: "DynamicContainer"
provide: "./release" # may be omitted

container:
  containerImage: "./source"
  flagTemplate: "JCC{Fl4g_Pr3f1x_[TEAM_HASH]}" # set dynamic flag format here. Ensure it ends with "_[TEAM_HASH]"
  exposePort: 1337 # port to expose
  memoryLimit: 128
  cpuCount: 1
  storageLimit: 256
  networkMode: "Isolated"
  enableTrafficCapture: false
```

Flag will be available as the container's environment variable `GZCTF_FLAG`. If flag must be placed in a file, consider adding a bash script `entrypoint.sh` that looks like this:

```bash
#!/bin/bash
echo "$GZCTF_FLAG" > /path/to/flag.txt
chmod 444 /path/to/flag.txt
unset GZCTF_FLAG
exec <command to run your service>
```

Then replace `CMD` in your Dockerfile to point to the `entrypoint.sh` script instead.

# Attack-Defense

Inside `attdef` folder, the file structure for each challenges should look like this:

```
<name>/
├── release/
│   └── ...
├── src/
│   └── ...
├── poc/
│   └── ...
├── challenge.yml
└── checker/
    └── ...
```

It is quite similar to jeopardy, with an addition of `checkers` folder and `source` renamed to `src`.

Explanation:

1. **\<name>** is the name of the challenge to be created.
2. **release** is the folder for the attachments to be given to the participants.
3. **src** is the folder used to store the original challenge source code AND the `Dockerfile`
4. **checker** is the folder used to run checkers for SLA.
5. **poc** is the folder that contains an explanation (or script) on each challenge's initial vulnerabilities.
6. **challenge.yml** serves the same purpose as in jeopardy version.

Template for `challenge.yml`:

```yml
name: "<CHALLENGE_TITLE>"
author: "<YOUR_NAME>"
category: "<Crypto|Pwn|Web|Reverse|Forensics>"

description: |
  Lorem ipsum dolor sit amet

type: "AttackDefense"

container:
  exposePort: 80 # adjust me
  memoryLimit: 64
  cpuCount: 1
  storageLimit: 256

ad:
  checkerImage: "checkers/<CHALL_NAME>:latest" # chall_name should be in kebab-case
  allowEgress: true
  allowSelfReset: true

provide: "./release" # omit if no attachment
```

`release/` and `poc/` remains unchanged. The instructions to fill `src/` and `checker/` is listed below.

#### src folder

`src/` MUST contain at least 2 files: `Dockerfile` and `supervisord.conf`.

- `Dockerfile` is used to build the challenge container the players will access. Fill with anything, but replace run with `supervisord` instead of the usual way you run your service:

```Dockerfile
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
```

- `supervisord.conf` has the actual command to run your service. Content is copied from [the example file](./attdef/example/src/supervisord.conf). `[program:svc]` is the only block you touch, and you may add more `program` blocks if necessary.

```conf
[program:svc]
command=python3 /service.py # change me, this cmd is executed to run your service
autostart=true
autorestart=true
startretries=1000000
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
```

> TL;DR: `Dockerfile` last directive is template (copied), `supervisord.conf` is mostly template (copied) except for the `[program]` blocks

#### checker folder

`checker/` MUST contain at least 4 files: `checker.py`, `run.py`, `checks.py`, and `Dockerfile`. Optionally, you can add a `requirements.txt` too

- `checker.py` and `run.py` are templates. Just copy them from [the example](./attdef/example/checker/).

- `Dockerfile` is usually unchanged too. Unless you need special modifications, just copy it from [the example](./attdef/example/checker/).

- `requirements.txt` (if you use them) usually contains `requests` library only. If you need another libraries for your checker, put them there.

- `checks.py` is the logic of your checkers to plant & check flag. This file will be ran each tick via docker. Simply decorate checker functions with `@check`. Refer to [the example file](./attdef/example/checker/checks.py) for further info.

> TL;DR: only `checks.py` needs to be edited; the rest (usually) can just be copy-pasted from the example

## TIA 🕵️
