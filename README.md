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

TBA

## TIA 🕵️
