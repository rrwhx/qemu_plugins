QEMU_DIR ?=${HOME}/qemu
GLIB_INC ?=$(shell pkg-config --cflags glib-2.0)
CXXFLAGS ?= -march=native -g -Wall -std=c++14 -march=native -iquote $(QEMU_DIR)/include/qemu/ $(GLIB_INC) -O2 -std=c++17 -MMD -MP
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

SOURCES := $(wildcard *.cc */*.cc)
OBJS := $(addprefix $(BUILD_DIR)/, $(addprefix lib, $(patsubst %.cc,%.so,$(SOURCES))))
SUBDIRS := util


NO_CAPSTONE_SOURCES := \
	bt_indirect.cc \
	champsim_la_with_reg.cc \
	icount.cc \
	icount_insn_cb2.cc \
	icount_insn_cb.cc \
	icount_insn_inline.cc \
	insn_perf.cc \
	insn_trace2.cc \
	insn_trace.cc \
	test.cc \
	trace.cc

NO_CAPSTONE_OBJS := $(addprefix $(BUILD_DIR)/, $(addprefix lib, $(patsubst %.cc,%.so,$(NO_CAPSTONE_SOURCES))))

all: $(OBJS) $(SUBDIRS)

no_capstone: $(NO_CAPSTONE_OBJS)

util: $(SUBDIRS)


$(SUBDIRS):
	$(MAKE) -C $@

$(QEMU_DIR):
	@echo "Folder $(QEMU_DIR) does not exist"
	false

$(BUILD_DIR)/lib%.so : %.cc
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -shared -fPIC -o $@ $< -ldl -lrt -lz

-include $(DEPS)

clean:
	rm -rf *.o *.so *.d $(BUILD_DIR)
	for dir in $(SUBDIRS); do \
	$(MAKE) -C $$dir -f Makefile $@; \
	done

.PHONY: all $(SUBDIRS)
