compile:
	gcc -o chall chall.c \
		-fstack-protector-all \
		-fPIE -pie \
		-Wl,-z,relro,-z,now \
		-Wl,-z,noexecstack \
		-fcf-protection=full \
		-lseccomp
