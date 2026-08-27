Recover seed with agcd
- https://eprint.iacr.org/2016/215.pdf
- https://github.com/Lyutoon/cryptography/blob/main/agcd.sage
- https://math.stackexchange.com/questions/1834472/approximate-greatest-common-divisor

Recover factor with quadratic equation
```
# n = a1a2 *z^2 + (a1b2+a2b1) * z^2 + b1b2
# (a1b2 + a2b1) * a2b1 = a1b1a2b2 + (a2b1)^2 ||| a1b2pa2b1 * x = a1b1a2b2 + x2
# a2b1 = (a1b1a2b2 + (a2b1)^2)//(a1b2 + a2b1) 
# x = a1b1a2b2 +x2 // a1b2pa2b1
# a1b2pa2b1x = a1b1a2b2 + x2
# x2 - a1b2pa2b1x +a1b1a2b2
# a = 1
# b = a1b2pa2b1
# c = a1b1a2b2
```
