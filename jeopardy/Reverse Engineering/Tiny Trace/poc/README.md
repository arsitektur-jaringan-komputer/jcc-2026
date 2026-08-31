# Tiny Trace - Proof of Concept

> JCC 2026 - Reverse Engineering - Hard - UrSourceCode

We were given a Windows x64 PE binary, tinytrace.exe. Loading it into IDA Free, we got some information:

- it is a console subsystem binary with a statically linked CRT, no packer
- the imports point at process and pipe APIs: CreatePipe, CreateProcessA, ReadFile, WriteFile, SetHandleInformation, GetModuleFileNameA
- the entry function scans argv for `--worker`, so the same file runs as two different programs

Reading the main function at `sub_1400013B0`, we got some information:

```c
for ( i = 1; i < argc; i++ )
    if ( !strcmp(argv[i], "--worker") )
        return sub_140001480(argc, argv);   // worker process
return sub_140001080();                       // parent process
```

1. if the flag is absent it calls `sub_140001080` (parent process)
2. if `--worker` is found it calls `sub_140001480` (worker process)

The parent process give us no logic, the main logic live on worker process.

### Worker Process

Jumping into `sub_140001480`, we get:

```c
__int64 __fastcall sub_140001480(int a1, __int64 a2)
{
  // a1 = argc, a2 = argv (typed as __int64, so a2+16 / a2+24 = argv[2] / argv[3])
  if ( a1 >= 4 )
  {
    v3 = (void *)sub_140008920(*(_QWORD *)(a2 + 16), 0, 0);   // argv[2] -> pipe handle
    v4 = (void *)sub_140008920(*(_QWORD *)(a2 + 24), 0, 0);   // argv[3] -> pipe handle
    v5 = 0;
    memset(v15, 0, sizeof(v15));                              // input buffer, 32 bytes
    do
    {
      NumberOfBytesRead = 0;
      if ( !ReadFile(v3, (char *)v15 + v5, 33 - v5, &NumberOfBytesRead, nullptr) )
        break;
      if ( NumberOfBytesRead == 0 )
        break;
      v5 += NumberOfBytesRead;
    }
    while ( v5 < 0x21 );

    if ( v5 > 1 )
    {
      v6 = *((_BYTE *)v15 + v5 - 1);
      if ( v6 == 10 || v6 == 13 )                             // strip ONE newline
        --v5;
    }

    if ( v5 == 32 )                                           // length gate
    {
      v13[0] = -1694934140;   // 0x9AF95B84
      v13[1] = -1679077175;   // 0x9BEB50C9
      v13[2] = 1447133548;    // 0x5641816C
      v13[3] = 1155090915;    // 0x44D949E3
      v13[4] = -47635199;     // 0xFD292501
      v13[5] = 1106827868;    // 0x41F8DA5C
      v13[6] = -991992481;    // 0xC4DF655F
      v13[7] = -1115445458;   // 0xBD83A72E   <- the 32-byte KEY
      for ( i = 0; i < 32; i++ )                              // decode expected
        v14[i] = byte_140019380[i]                            // ENCODED_EXPECTED
               ^ *((_BYTE *)v13 + (i + 5) % 32)               // ^ KEY rotated by 5
               ^ 0xC3;                                        // ^ constant
      v7 = 0;
      while ( byte_140019360[(unsigned __int8)byte_140019340[v7]]      // ADD[PERM[i]]
            + (*((_BYTE *)v15 + (unsigned __int8)byte_140019340[v7])   // ^ input[PERM[i]]
             ^ *((_BYTE *)v13 + (unsigned __int8)byte_140019340[v7]))  // ^ KEY[PERM[i]]
            == v14[(unsigned __int8)byte_140019340[v7]] )              // == EXP[PERM[i]]
      {
        if ( ++v7 >= 32 )
        {
          v8 = 1;                                             // all 32 passed
          goto LABEL_17;
        }
      }
      v8 = 0;                                                 // first mismatch
LABEL_17:
      WriteFile(v4, &v8, 1u, &NumberOfBytesWritten, nullptr); // 1-byte verdict
      CloseHandle(v3);
      CloseHandle(v4);
    }
    else
    {
      WriteFile(v4, "\x00", 1u, ...);                         // wrong length -> instant reject
    }
  }
  return 0;
}
```

Reading it:

1. the parent printed the two pipe handles as decimal text into the command line (`--worker <in> <out>`), the func `sub_140008920` is just a strtoull-style CRT helper that parses the number back into a handle
2. the read loop pulls up to 33 bytes, strips one `\n/\r`, and requires exactly 32 left, so the code is 32 chars
3. `v13` (8 dwords) is a 32-byte key table
4. the while condition is the entire check

Checking each symbol in IDA, we got:

- `0x140019340` contains every value 0..31 exactly once, it is a permutation of the check order
- `0x140019360` is just `13 29` repeated as a constant addend
- `0x140019380` is 32 high-entropy bytes as the ENCODED expected values

Rename it, we got:

```c
i = 0;
while ( true )
{
    idx = PERM[i];                                 // which character gets checked now

    if ( ADD[idx] + (input[idx] ^ key[idx])        // compute...
         != EXP[idx] )                             // ...compare
        break;                                     // mismatch -> fall out, v8 = 0

    ++i;                                           // char survived -> next round
    if ( i >= 32 ) { v8 = 1; goto reply; }         // survived all 32 -> success
}
v8 = 0;
```

That is the whole check.

### The key

`v13` is not computed at run time from the LCG-looking loop above it either. The compiler folded `gen_key` into immediates, so the key is a hard-coded 32-byte constant written straight into the stack:

```c
v13[0] = 0x9AF95B84;
v13[1] = 0x9BEB50C9;
v13[2] = 0x5641816C;
v13[3] = 0x44D949E3;
v13[4] = 0xFD292501;
v13[5] = 0x41F8DA5C;
v13[6] = 0xC4DF655F;
v13[7] = 0xBD83A72E;
```

Reading it:

1. these are 32-bit dwords, so the byte order inside each one is reversed (little-endian). `0x9AF95B84` is bytes `84 5B F9 9A`, not `9A F9 5B 84`
2. flattening all 8 dwords LSB-first gives the key as raw bytes

```text
84 5B F9 9A C9 50 EB 9B 6C 81 41 56 E3 49 D9 44
01 25 29 FD 5C DA F8 41 5F 65 DF C4 2E A7 83 BD
```

### The expected values

`EXP` is not a plain table. The bytes at `0x140019380` are stored encoded and get decoded onto the stack before the loop:

```c
EXP[i] = ENCODED_EXPECTED[i] ^ key[(i + 5) % 32] ^ 0xC3
```

Reading it:

1. the decode loop sits right before the comparison loop in `worker_main`
2. it uses the same 32-byte key, rotated by 5, and a constant `0xC3`
3. so the static path is: read `ENCODED_EXPECTED` from `.rdata`, decode it with the key above, then invert

```text
e1 41 cd 0a c2 89 9a 20 6f 1f 31 8a 9e a3 99 50
7c 3d 58 c2 16 e1 9d 9b 7e 37 c2 1d 32 f2 0a e9
```

### The inversion

The check enforces, byte-sized:

```text
EXP[idx] = (input[idx] ^ KEY[idx]) + ADD[idx]   (mod 256)
```

XOR flips bits before the add, so undo the add first, then the XOR:

```text
input[idx] = (EXP[idx] - ADD[idx]) mod 256  ^  KEY[idx]
```

Reading it:

1. `EXP`, `ADD`, `KEY` are all indexed by the same `idx` (the flag position), so the inversion is per-position and independent
2. `PERM` only decides the order the loop checks them in. It never changes which `EXP/ADD/KEY` pair goes with which character, so we don't even have to un-permute anything
3. subtract/add and XOR are byte ops: `(a + b) mod 256` inverts to `(c - b) mod 256`; `a ^ b` inverts to `c ^ b`

Plug it in for every `idx` from 0..31 and then:

```python
KEY = bytes.fromhex("845bf99ac950eb9b6c814156e349d944"
                    "012529fd5cdaf8415f65dfc42ea783bd")
ADD = bytes([0x13, 0x29] * 16)
ENC = bytes.fromhex("726995a5800b0f00e505b6487849a7cf"
                    "6506da5eb0fd9a761a77bc5aaac853e3")
EXP = bytes(ENC[i] ^ KEY[(i + 5) % 32] ^ 0xC3 for i in range(32))

flag = bytes(((EXP[i] - ADD[i]) & 0xFF) ^ KEY[i] for i in range(32))
print(flag.decode())
```

```text
JCC{f0ll0w_7h3_ch1ld_br34kp01nt}
```

### Dynamic solve (WinDbg)

The flag also falls out of a live debugging session. Since the worker is a child process, we tell the debugger to follow it:

```text
0:000> .childdbg 1
Processes created by the current process will be debugged
0:000> g
```

`g` runs the parent, which spawns the worker with `--worker <in> <out>`. The debugger attaches to the child and stops at its initial break (`ntdll!LdrpDoDebuggerBreak`). The parent feeds our input through the pipe, so we type any 32-character wrong candidate, for example 32 A's, at the program's prompt.

ASLR is on, so we address everything module-relative. The compare instruction is at `tinytrace+0x160C` (`cmp al, [rbp+rcx-0x11]`), and the `jne` that aborts on the first mismatch is a 2-byte short jump at `tinytrace+0x1610`:

```text
1:002> bp tinytrace+0x160C ".printf \"HIT idx=%d add=%02x key=%02x exp=%02x\\n\", @rcx, by(@r8+@rcx+0x19360), by(@rbp+@rcx-0x31), by(@rbp+@rcx-0x11); eb tinytrace+0x1610 90 90; gc"
1:002> g
```

Reading the breakpoint command:

1. `@rcx` holds `idx`, the flag position checked this round (loaded from `PERM`)
2. `by(@r8+@rcx+0x19360)` reads `ADD[idx]` from `.rdata` (R8 holds the image base)
3. `by(@rbp+@rcx-0x31)` reads `KEY[idx]` from the stack, `by(@rbp+@rcx-0x11)` reads `EXP[idx]` next to it
4. `eb tinytrace+0x1610 90 90` replaces the `jne` with two NOPs, so a wrong candidate no longer exits the loop at the first mismatch and all 32 iterations execute
5. `gc` resumes with the recorded flags, so the loop runs on to the next hit

Each checked character prints one `HIT` line:

```text
HIT idx=7 add=29 key=9b exp=20
HIT idx=1 add=29 key=5b exp=41
HIT idx=9 add=29 key=81 exp=1f
HIT idx=16 add=13 key=01 exp=7c
...
HIT idx=4 add=13 key=c9 exp=c2
HIT idx=11 add=29 key=56 exp=8a
```

Reading the output:

1. the first line can interleave with a checksum `WARNING` from symbol resolution
2. the `idx` values arrive in `PERM` order (7, 1, 9, 16, ...), not 0..31, so sort the hits by `idx` before inverting
3. the `key` and `exp` bytes match the static tables exactly (`idx=0` gives `84`, `idx=1` gives `5b`, `idx=7` gives `9b`), confirming the compiler-folded stack key and the decoded expected values

Each line is one position of the transform, so the inversion from the static path applies unchanged, fed from registers instead of `.rdata`:

```python
hits = [(7,0x29,0x9b,0x20),(1,0x29,0x5b,0x41),(9,0x29,0x81,0x1f),(16,0x13,0x01,0x7c),
        ...]  # (idx, add, key, exp) for all 32 hits
hits.sort()
print(''.join(chr(((exp - add) & 0xFF) ^ key) for idx, add, key, exp in hits))
```

```text
JCC{f0ll0w_7h3_ch1ld_br34kp01nt}
```

The dynamic solve needed two facts about the binary: the address of the compare instruction and the layout of its operands. `ADD`, `KEY`, `EXP` and the permutation all came from the breakpoint's register reads at run time.
