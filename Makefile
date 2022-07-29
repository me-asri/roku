SRCDIR := src
INCDIR := inc
OBJDIR := obj
BINDIR := bin

SRCEXT := c
DEPEXT := h
OBJEXT := o

CC     := gcc
CFLAGS := -std=gnu11 -Wall -Werror -O2 -g
INC    := -I$(INCDIR)
LIB    :=

TARGET := roku

SRCS   := $(wildcard $(SRCDIR)/*.$(SRCEXT) $(SRCDIR)/**/*.$(SRCEXT))
DEPS   := $(wildcard $(INCDIR)/*.$(DEPEXT) $(INCDIR)/**/*.$(DEPEXT))
OBJS   := $(patsubst $(SRCDIR)/%, $(OBJDIR)/%, $(SRCS:.$(SRCEXT)=.$(OBJEXT)))
BIN    := $(BINDIR)/$(TARGET)

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJS)
	@mkdir -p $(BINDIR)

	$(CC) -o $(BIN) $^ $(LIB)
	@echo Compiled $(TARGET)

$(OBJDIR)/%.$(OBJEXT): $(SRCDIR)/%.$(SRCEXT) $(DEPS)
	@mkdir -p $(dir $@)

	$(CC) -c -o $@ $< $(CFLAGS) $(INC)

clean:
	$(RM) -r $(BINDIR) $(OBJDIR)
