# liboffsetfinder64
A 64bit offsetfinder. It finds offsets, patches, parses Mach-O and even supports IMG4

### Installation / Getting started
Debian / Ubuntu Linux
## First install all required dependencies and build tools:

sudo apt-get install \
	build-essential \
	checkinstall \
	git \
	autoconf \
	automake \

## Then clone the actual project repository:

git clone https://github.com/thimstar/liboffsetfinder64.git
cd liboffsetfinder64

## Now you can build and install it:

./autogen.sh

make

sudo make install
