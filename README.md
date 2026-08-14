# JCC 2026

Collection of challenges for JCC 2026 competition

# Jeopardy

Inside `jeopardy` folder, the file structure for each challenges should look like this:

```
<name>/
├── release/
│   └── ...
├── source/
│   └── <name>/
│       └── ...
└── poc/
    └── ...
└── README.md
```

Explanation:

1. **\<name>** is the name of the challenge to be created.
2. **release** is the folder for the attachments to be given to the participants.
3. **source** is the folder used to store the original challenge source code, and if it’s a service, this folder will be deployed to the server. Please include `Dockerfile` or `docker-compose.yml`

> Why does the source folder need another \<name>?  
> To avoid conflicts in docker compose so they don’t sync with each other

1. **poc** is the folder that contains an explanation (or script) on how to solve each challenge (mandatory).
2. **README.md** is used to provide a description of each challenge. Below is a README.md template that can be used.

```md
# <name>

## Author

(username)

## Difficulty

Easy/Medium/Hard

## Description

lorem ipsum dolor sit amet.

JCC{example_flag}
```

# Attack-Defense

TBA

## TIA 🕵️
