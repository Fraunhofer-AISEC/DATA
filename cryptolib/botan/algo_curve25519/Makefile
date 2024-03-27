all: curve25519

curve25519: curve25519.cpp
	mkdir -p bin
	g++-11 -std=c++20 -g -O0 -Wall -I ../botan/build/include -Wl,-rpath=../botan/ $^ -o bin/$@ -L ../botan/ -l:libbotan-3.a

clean:
	rm -rf bin/
