CC=gcc
CXX=g++
RM=rm -f
CPPFLAGS=-g -O2
LDFLAGS=-g
LDLIBS=

SRCS=$(wildcard *.cc)
OBJS=$(subst .cc,.o,$(SRCS))
BINS=$(subst .cc,,$(SRCS))
DEPS := $(BINS:=.d)
$(info $$SRCS is [${SRCS}])
$(info $$BINS is [${BINS}])
$(info $$DEPS is [${DEPS}])

all: $(BINS)

$(BINS):
	$(CXX) $(LDFLAGS) -MMD -o $@ $@.cc $(LDLIBS)

clean:
	$(RM) $(BINS)

distclean: clean
	$(RM) *~ $(DEPS)

-include $(DEPS)

.PHONY: all


