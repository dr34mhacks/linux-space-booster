.PHONY: check test shellcheck

test:
	bash tests/test_phase1.sh
	bash tests/test_phase2.sh
	bash tests/test_phase3.sh
	bash tests/test_phase4.sh

shellcheck:
	@command -v shellcheck >/dev/null 2>&1 || { echo "ShellCheck is not installed"; exit 1; }
	shellcheck -x linux_space_booster.sh tests/test_phase1.sh tests/test_phase2.sh tests/test_phase3.sh tests/test_phase4.sh

check: test
