BIN1 = memod
BIN1_SRCS = memod.c

BIN2 = memo
BIN2_SRCS = cli.c

LIB1 = libmemo
LIB1_SRCS = client.c logging.c server.c

SRC_DIR = src
BUILD_DIR = build
TEST_DIR = test

DLIBS = -luring
SLIBS = -lmemo

# Define objects to be built and where to put them
BIN1_OUT = $(addprefix $(BUILD_DIR)/, $(BIN1))
BIN1_OBJS = $(BIN1_SRCS:%.c=$(addprefix $(BUILD_DIR)/, %.o))
BIN1_DEPS = $(BIN1_OBJS:%.o=%.d)
BIN2_OUT = $(addprefix $(BUILD_DIR)/, $(BIN2))
BIN2_OBJS = $(BIN2_SRCS:%.c=$(addprefix $(BUILD_DIR)/, %.o))
BIN2_DEPS = $(BIN2_OBJS:%.o=%.d)
LIB1_OUT = $(addprefix $(BUILD_DIR)/, $(LIB1))
LIB1_OBJS = $(LIB1_SRCS:%.c=$(addprefix $(BUILD_DIR)/, %.o))
LIB1_DEPS = $(LIB1_OBJS:%.o=%.d)

CFLAGS = -g -I. -I /usr/local/include -Wall -Wextra -Wpedantic

# Python virtualenv setup
VENV_DIR = .venv
PYTHON = $(VENV_DIR)/bin/python
PIP = $(VENV_DIR)/bin/pip
PYTEST = $(VENV_DIR)/bin/pytest

$(BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	@echo $(COMPILE.c) -MMD -fpic -o $@ $<
	@$(COMPILE.c) -MMD -fpic -o $@ $<

all : dirs $(LIB1_OUT) $(BIN1_OUT) $(BIN2_OUT)

$(BIN1_OUT) : $(BIN1_OBJS)
	$(LINK.c) $^ -Wl,-Bstatic -L$(BUILD_DIR) $(SLIBS) -Wl,-Bdynamic $(DLIBS) -o $@

$(BIN2_OUT) : $(BIN2_OBJS)
	$(LINK.c) $^ -Wl,-Bstatic -L$(BUILD_DIR) $(SLIBS) -Wl,-Bdynamic $(DLIBS) -o $@

$(LIB1_OUT) : $(LIB1_OUT).so $(LIB1_OUT).a

$(LIB1_OUT).so : $(LIB1_OBJS)
	$(LINK.c) $^ -shared $(DLIBS) -o $@

$(LIB1_OUT).a : $(LIB1_OBJS)
	ar rcs $@ $^

-include $(LIB1_DEPS) $(BIN1_DEPS) $(BIN2_DEPS)

# Create virtualenv and install requirements
$(VENV_DIR)/bin/activate : $(TEST_DIR)/requirements.txt
	python -m venv $(VENV_DIR)
	$(PIP) install -r $(TEST_DIR)/requirements.txt
	touch $@

.PHONY: dirs clean test

# Run tests with virtualenv
test : $(BIN1_OUT) $(VENV_DIR)/bin/activate
	$(PYTEST) $(TEST_DIR)/test_memo.py

dirs :
	@mkdir -p $(BUILD_DIR)

clean :
	rm -rf $(BIN1_OBJS) $(BIN1_DEPS) $(BIN1_OUT) \
		$(BIN2_OBJS) $(BIN2_DEPS) $(BIN2_OUT) \
		$(LIB1_OBJS) $(LIB1_DEPS) $(LIB1_OUT).a $(LIB1_OUT).so \
		$(VENV_DIR)
