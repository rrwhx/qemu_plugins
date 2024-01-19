CC=gcc
CXX=g++
RM=rm -f
CPPFLAGS=-g -O2
CFLAGS=-g -O2
LDFLAGS=-g
LDLIBS=

BUILD_DIR := ./build
SRC_DIRS := ./

CPPSRCS=$(wildcard *.cc)
CPPOBJS=$(subst .cc,.o,$(CPPSRCS))
CPPBINS=$(addprefix $(BUILD_DIR)/, $(subst .cc,,$(CPPSRCS)))
CSRCS=$(wildcard *.c)
COBJS=$(subst .c,.o,$(CSRCS))
CBINS=$(addprefix $(BUILD_DIR)/, $(subst .c,,$(CSRCS)))

BIN=${CPPBINS} ${CBINS}

DEPS := $(CPPBINS:=.d)
$(info $$CPPSRCS is [${CPPSRCS}])
$(info $$CPPBINS is [${CPPBINS}])
$(info $$DEPS is [${DEPS}])
$(info $$BIN is [${BIN}])

all: $(BIN)

$(BUILD_DIR)/%: %.cc
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -o $@ $<

$(BUILD_DIR)/%: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -o $@ $<

clean:
	$(RM) -rf $(BUILD_DIR)

distclean: clean
	$(RM) *~ $(DEPS)

-include $(DEPS)

.PHONY: all


