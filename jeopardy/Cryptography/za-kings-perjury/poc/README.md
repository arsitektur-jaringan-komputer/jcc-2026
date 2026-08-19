basic schnorr protocol, challenge is between 1-5

1. pick any number `Z`
2. predict chall by picking any number between 1-5 as `e_guess`
3. calculate inverse of public key: `Y_inv = Y ^ -1`
4. calculate `R = g^z * Y_inv^e_guess`

Then send `R` in first question and `Z` in second question. If `e` from server matches `e_guess`, gain flag (20% chance each connection)
