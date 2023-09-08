all: ecdh

ecdh: ecdh.cpp
	mkdir -p bin
	g++-11 -std=c++20 -g -O3 -Wall -I ../botan/build/include -Wl,-rpath=../botan/ $^ -o bin/$@ -L ../botan/ -l:libbotan-3.a

clean:
	rm -rf bin/
