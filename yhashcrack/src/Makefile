CC=gcc
NT=12
MODE=
HASH_SHA_256=a128c974e1c581ac4fc0acb3a4df3fcd7a94a3d760d8a734c1d5d8882f6c512a 96d23efbff9738760eaf90438303139c835e3fec8446445596d481dcf061312d 3b8474265ae06009f68f0df2e66ec3c2fb5ceb954ef19941d35b775d677fbfa3 a0695c2b131e25019cba45b15122d4d26172ee4214457b6c0dc63d2ae8bea087 790fc7018af9f002142a48dab4a349627aa72b78b811841fd132fc898764dd26 f1a70768029bab7cef2a47a24e4e9819f3c03cd98ea6dd0a134c1563d8656eab 9515818c1aef58b2a8e01024c64dd9e47ccee343ae0cf8bd01f31c3d7514f005
DICTIONARY=dictionary/passwordsClean.txt

all:
	$(CC) -g3 -Wall -Wextra -Ofast yhashcrack.c -o yhashcrack -lyhash -Lyhash/ -lm -lpthread -fopenmp
	- $(CC) -g3 -Wall -Wextra -Ofast yhashcrackSSL.c -o yhashcrackSSL -lyhash -Lyhash/ -lm -lpthread -fopenmp -lssl -lcrypto
	$(CC) -g3 -Wall -Wextra -Ofast yhashcrackOPT.c -o yhashcrackOPT -lyhash -Lyhash/  -lm -lpthread -fopenmp
	$(CC) -g3 -Wall -Wextra -Ofast yhashcrackPRE.c -o yhashcrackPRE -lyhash -Lyhash/ -lm -lpthread -fopenmp

run_md5:
	@echo "MD5: Hello"
	@LD_LIBRARY_PATH=yhash/ ./yhashcrack$(MODE) md5 $(NT) $(DICTIONARY) 8b1a9953c4611296a827abf8c47804d7

run_sha1:
	@echo "SHA1: Hello"
	@LD_LIBRARY_PATH=yhash/ ./yhashcrack$(MODE) sha1 $(NT) $(DICTIONARY) f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0

run_sha224:
	@echo "SHA224: Hello"
	@LD_LIBRARY_PATH=yhash/ ./yhashcrack$(MODE) sha224 $(NT) $(DICTIONARY) 4149da18aa8bfc2b1e382c6c26556d01a92c261b6436dad5e3be3fcc

run_sha256:
	@LD_LIBRARY_PATH=yhash/:FastMemcpy/ ./yhashcrack$(MODE) sha256 $(NT) $(DICTIONARY) $(HASH_SHA_256)

run_sha512:
	@echo "SHA512: Hello"
	@LD_LIBRARY_PATH=yhash/ ./yhashcrack$(MODE) sha512 $(NT) $(DICTIONARY) 3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315

run_dead256:
	@echo "SHA256: Kojak"
	@LD_LIBRARY_PATH=yhash/ ./yhashcrack$(MODE) sha256 $(NT) $(DICTIONARY) aa06d86e3caac2d288d1591d13a414958765b22dd5a3b12b8d46560327ef9c41
	@echo

run_dead512:
	@echo "SHA512: Kojak"
	@LD_LIBRARY_PATH=yhash/ ./yhashcrack sha512 $(NT) $(DICTIONARY) 4caf93fc2b76a082c6e8f1a6dd7442792519da79f977e8aaa812ea727b17ba96c3f12ad6f9283ea8e458dfb8e7929c55b0fe30c082843d2dd75c71aa219b9772
	@echo

gdb256:
	gdb -ex "set environment LD_LIBRARY_PATH=yhash/" --args ./yhashcrack$(MODE) sha256 $(NT) $(DICTIONARY) $(HASH_SHA_256)

clean:
	rm -Rf *~ yhashcrack
	rm -Rf *~ yhashcrackOPT
	rm -Rf *~ yhashcrackPRE
	rm -Rf *~ yhashcrackSSL