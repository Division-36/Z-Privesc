# Z-Privesc - Build System
# https://github.com/Division-36/Z-Privesc

CC          ?= cc
PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin
MANDIR      := $(PREFIX)/share/man/man1
NAME        := z_privesc
VERSION     := 1.0.0
BUILD_DATE  := $(shell date -u +%Y-%m-%d)
GIT_SHA     := $(shell git rev-parse --short=8 HEAD 2>/dev/null || echo "00000000")
BUILD_ID    := Z-PRIVESC-$(shell date -u +%Y%m%d)-$(GIT_SHA)

CFLAGS_BASE := -std=gnu99 -Wall -Wextra -Wpedantic -Werror \
               -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 \
               -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE \
               -DBUILD_ID=\"$(BUILD_ID)\" -DVERSION=\"$(VERSION)\"

CFLAGS      := $(CFLAGS_BASE) -Iinclude
TEST_CFLAGS  := $(CFLAGS_BASE) -Iinclude -Itests -Wno-unused-result -Wno-format-truncation
LDFLAGS     := -Wl,-z,relro,-z,now -Wl,--as-needed
LIBS        :=

DEBUG_CFLAGS := $(CFLAGS_BASE) -g3 -O0 -fno-omit-frame-pointer
COV_CFLAGS   := $(CFLAGS_BASE) -g3 -O0 --coverage
COV_LDFLAGS  := --coverage

SRC_DIR     := src
OBJ_DIR     := build/obj
BIN_DIR     := build/bin

CORE_SRCS    := $(SRC_DIR)/main.c \
                $(SRC_DIR)/probe_runner.c \
                $(SRC_DIR)/log.c \
                $(SRC_DIR)/util.c \
                $(SRC_DIR)/crypto.c \
                $(SRC_DIR)/audit.c \
                $(SRC_DIR)/risk.c

TRUTH_SRCS   := $(SRC_DIR)/truthimatics/engine.c \
                $(SRC_DIR)/truthimatics/evidence.c

PROBE_SRCS   := $(SRC_DIR)/probes/suid.c \
                $(SRC_DIR)/probes/writable_path.c \
                $(SRC_DIR)/probes/capabilities.c \
                $(SRC_DIR)/probes/writable_etc.c \
                $(SRC_DIR)/probes/docker_socket.c \
                $(SRC_DIR)/probes/polkit.c \
                $(SRC_DIR)/probes/world_writable.c \
                $(SRC_DIR)/probes/kernel_vuln.c \
                $(SRC_DIR)/probes/cron.c \
                $(SRC_DIR)/probes/sudoers.c \
                $(SRC_DIR)/probes/ssh_keys.c \
                $(SRC_DIR)/probes/groups.c \
                $(SRC_DIR)/probes/service.c \
                $(SRC_DIR)/probes/kernel_hardening.c \
                $(SRC_DIR)/probes/process.c \
                $(SRC_DIR)/probes/nfs.c \
                $(SRC_DIR)/probes/ld_preload.c

SRCS         := $(CORE_SRCS) $(TRUTH_SRCS) $(PROBE_SRCS)
OBJS         := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
DEPS         := $(OBJS:.o=.d)

BIN          := $(BIN_DIR)/$(NAME)

TEST_SRCS    := tests/test_main.c \
                tests/test_suid.c \
                tests/test_writable_path.c \
                tests/test_capabilities.c \
                tests/test_writable_etc.c \
                tests/test_docker_socket.c \
                tests/test_polkit.c \
                tests/test_world_writable.c \
                tests/test_kernel_vuln.c \
                tests/test_truthimatics.c \
                tests/test_risk.c \
                tests/test_audit.c \
                tests/test_util.c \
                tests/test_edge_cases.c

TEST_OBJS    := $(patsubst tests/%.c,$(OBJ_DIR)/tests/%.o,$(TEST_SRCS))
TEST_BIN     := $(BIN_DIR)/test_$(NAME)
TEST_LIBS    := -lm

INTEG_BIN    := $(BIN_DIR)/test_integration

.PHONY: all clean install uninstall test test-full coverage static release \
        help dirs

all: dirs $(BIN)

dirs:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

$(BIN): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "==> Built $(NAME) $(VERSION) [$(BUILD_ID)]"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(OBJ_DIR)/tests/%.o: tests/%.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -MMD -MP -c -o $@ $<

$(TEST_BIN): $(filter-out $(OBJ_DIR)/main.o,$(OBJS)) $(TEST_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS_BASE) -Iinclude $(LDFLAGS) -o $@ $^ $(TEST_LIBS) $(LIBS)
	@echo "==> Built test suite"

$(INTEG_BIN): tests/test_integration.c $(filter-out $(OBJ_DIR)/main.o,$(OBJS))
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(TEST_LIBS) $(LIBS)
	@echo "==> Built integration test"

test: $(TEST_BIN)
	@echo "==> Running unit tests"
	./$(TEST_BIN)

test-full: $(INTEG_BIN)
	@echo "==> Running integration tests (requires root)"
	./$(INTEG_BIN)

coverage: clean
	$(MAKE) CFLAGS="$(COV_CFLAGS)" LDFLAGS="$(COV_LDFLAGS)" $(TEST_BIN)
	./$(TEST_BIN)
	@mkdir -p build/coverage
	@find $(OBJ_DIR) -name "*.gcda" -o -name "*.gcno" | xargs -I{} cp {} build/coverage/ 2>/dev/null || true
	@find $(OBJ_DIR)/src -name "*.gcno" | xargs gcov 2>/dev/null >/dev/null || true
	@mv *.gcov build/coverage/ 2>/dev/null || true
	@echo "==> Coverage report in build/coverage/"

static: clean
	$(MAKE) CFLAGS="$(CFLAGS_BASE) -static" LDFLAGS="-static"
	@echo "==> Static build complete"

release: static
	@mkdir -p dist
	@strip $(BIN)
	@tar -czf dist/$(NAME)-$(VERSION)-linux-x86_64.tar.gz -C $(BIN_DIR) $(NAME)
	@echo "==> Release tarball: dist/$(NAME)-$(VERSION)-linux-x86_64.tar.gz"

install: $(BIN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(NAME)
	install -d $(DESTDIR)$(MANDIR)
	install -m 0644 man/$(NAME).1 $(DESTDIR)$(MANDIR)/$(NAME).1
	@echo "==> Installed $(NAME) to $(DESTDIR)$(BINDIR)"
	@echo "==> Installed man page to $(DESTDIR)$(MANDIR)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(NAME)
	rm -f $(DESTDIR)$(MANDIR)/$(NAME).1
	@echo "==> Uninstalled $(NAME)"

clean:
	rm -rf build dist
	find . -name "*.gcov" -delete 2>/dev/null || true

help:
	@echo "Z-Privesc $(VERSION) - Build Targets"
	@echo ""
	@echo "  all          Build z_privesc binary (default)"
	@echo "  test         Build and run unit tests"
	@echo "  test-full    Run integration tests on real testbeds (requires root)"
	@echo "  coverage     Build with gcov and emit coverage report"
	@echo "  static       Build a portable static binary"
	@echo "  release      Static + strip + release tarball"
	@echo "  install      Install binary and man page to PREFIX"
	@echo "  uninstall    Remove installed files"
	@echo "  clean        Remove all build artifacts"

-include $(DEPS)
