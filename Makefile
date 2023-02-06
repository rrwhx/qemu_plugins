QEMU_DIR ?=/home/lxy/qemu
GLIB_INC ?=`pkg-config --cflags glib-2.0`
CXXFLAGS ?= -g -Wall -std=c++14 -march=native -iquote $(QEMU_DIR)/include/qemu/ $(GLIB_INC) -O2 -std=c++17 -MMD -MP
#-I/home/lxy/github/capstone/include/
ifeq ($(wildcard $(QEMU_DIR)),)
    $(error $$QEMU_DIR [$(QEMU_DIR)] not exsited)
endif

BUILD_DIR := ./build
SRC_DIRS := ./

SOURCES := $(wildcard *.cc */*.cc)
OBJS := $(addprefix $(BUILD_DIR)/, $(addprefix lib, $(patsubst %.cc,%.so,$(SOURCES))))
DEPS := $(OBJS:.so=.d)

$(info $$SOURCES is [${SOURCES}])
$(info $$OBJS is [${OBJS}])
$(info $$DEPS is [${DEPS}])




all: $(OBJS)

$(QEMU_DIR):
	@echo "Folder $(QEMU_DIR) does not exist"
	false

$(BUILD_DIR)/lib%.so : %.cc
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -shared -fPIC -o $@ $< -ldl -lrt -lz

-include $(DEPS)

clean:
	rm -rf *.o *.so *.d $(BUILD_DIR)
