QEMU_DIR ?=/home/lxy/qemu
GLIB_INC ?=`pkg-config --cflags glib-2.0`
CXXFLAGS ?= -g -Wall -std=c++14 -march=native -iquote $(QEMU_DIR)/include/qemu/ $(GLIB_INC) -O2 -std=c++17
#-I/home/lxy/github/capstone/include/

all: libtest.so librvreg.so libinst_cat.so libicount.so 

libtest.so: test.cc
	$(CXX) $(CXXFLAGS) -shared -fPIC -o $@ $< -ldl -lrt -lz

librvreg.so: rvreg.cc
	$(CXX) $(CXXFLAGS) -shared -fPIC -o $@ $< -ldl -lrt -lz

libinst_cat.so: inst_cat.cc
	$(CXX) $(CXXFLAGS) -shared -fPIC -o $@ $< -ldl -lrt -lz
# /home/lxy/capstone/libcapstone.a

libicount.so: icount.cc
	$(CXX) $(CXXFLAGS) -shared -fPIC -o $@ $< -ldl -lrt -lz

clean:
	rm -f *.o *.so
