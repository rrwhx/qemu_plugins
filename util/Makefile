CC=gcc
CXX=g++
RM=rm -f
CPPFLAGS=-g -O2
LDFLAGS=-g
LDLIBS=

BUILD_DIR := ./build
SRC_DIRS := ./

SOURCES := $(wildcard *.cc */*.cc)
OBJS := $(addprefix $(BUILD_DIR)/, $(addprefix lib, $(patsubst %.cc,%.so,$(SOURCES))))

SRCS=$(wildcard *.cc)
OBJS=$(subst .cc,.o,$(SRCS))
BINS=$(addprefix $(BUILD_DIR)/, $(subst .cc,,$(SRCS)))
DEPS := $(BINS:=.d)
$(info $$SRCS is [${SRCS}])
$(info $$BINS is [${BINS}])
$(info $$DEPS is [${DEPS}])

all: $(BINS)

$(BUILD_DIR)/%: %.cc
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -o $@ $<

clean:
	$(RM) $(BINS)

distclean: clean
	$(RM) *~ $(DEPS)

-include $(DEPS)

.PHONY: all


