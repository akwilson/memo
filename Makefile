BIN1 = memod
BIN1_SRCS = memod.c server.c logging.c

#BIN2 = memo
#BIN2_SRCS = cli.c

LIBS = -luring

SRC_DIR = src
BUILD_DIR = build
TEST_DIR = test

# Define objects to be built and where to put them
BIN1_OUT = $(addprefix $(BUILD_DIR)/, $(BIN1))
BIN1_OBJS = $(BIN1_SRCS:%.c=$(addprefix $(BUILD_DIR)/, %.o))
BIN1_DEPS = $(BIN1_OBJS:%.o=%.d)
BIN2_OUT = $(addprefix $(BUILD_DIR)/, $(BIN2))
BIN2_OBJS = $(BIN2_SRCS:%.c=$(addprefix $(BUILD_DIR)/, %.o))
BIN2_DEPS = $(BIN2_OBJS:%.o=%.d)

CFLAGS = -g -I. -I /usr/local/include -Wall -Wextra -Wpedantic
#LDFLAGS = -linker_flags

# Python virtualenv setup
VENV_DIR = .venv
PYTHON = $(VENV_DIR)/bin/python
PIP = $(VENV_DIR)/bin/pip
PYTEST = $(VENV_DIR)/bin/pytest

$(BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	@echo $(COMPILE.c) -MMD -o $@ $<
	@$(COMPILE.c) -MMD -o $@ $<

all : dirs $(BIN1_OUT) $(BIN2_OUT)

$(BIN1_OUT) : $(BIN1_OBJS)
	$(LINK.c) $^ $(LIBS) -o $@

$(BIN2_OUT) : $(BIN2_OBJS)
	$(LINK.c) $^ $(LIBS) -o $@

-include $(BIN1_DEPS)

# Create virtualenv and install requirements
$(VENV_DIR)/bin/activate : $(TEST_DIR)/requirements.txt
	python -m venv $(VENV_DIR)
	$(PIP) install -r $(TEST_DIR)/requirements.txt
	touch $@

# Run tests with virtualenv
test : $(BIN1_OUT) $(VENV_DIR)/bin/activate
	$(PYTEST) $(TEST_DIR)/test_memo.py

.PHONY: dirs clean
dirs :
	@mkdir -p $(BUILD_DIR)

clean :
	rm -rf $(BIN1_OBJS) $(BIN1_DEPS) $(BIN1_OUT) \
		$(BIN2_OBJS) $(BIN2_DEPS) $(BIN2_OUT) \
		$(VENV_DIR)
