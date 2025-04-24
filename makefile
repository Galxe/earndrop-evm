fmt:
	forge fmt

clean:
	forge clean

build:
	forge build --via-ir

test:
	forge test

coverage:
	forge coverage


build_vesting:
	forge build --via-ir --contracts src/VestingEarndrop/VestingEarndrop.sol

deploy_vesting_earndrop:
	forge script script/VestingEarndrop/01_Deploy.s.sol:VestingEarndropScript --broadcast --verify -vvvv

.PHONY: test coverage build_vesting help format format-check lint lint-fix slither

# Set default target to help
.DEFAULT_GOAL := help

# Glob pattern for Solidity files
SOL_FILES = 'src/**/*.sol'

help: ## Display help information
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

format: ## Format all Solidity files
	@echo "Formatting Solidity files..."
	@npx prettier --write $(SOL_FILES) || yarn prettier --write $(SOL_FILES)

format-check: ## Check Solidity file formatting without modifying
	@echo "Checking Solidity file formatting..."
	@npx prettier --check $(SOL_FILES) || yarn prettier --check $(SOL_FILES)

lint: ## Check Solidity code with Solhint
	@echo "Linting Solidity files..."
	@npx solhint $(SOL_FILES) || yarn solhint $(SOL_FILES)

lint-fix: ## Fix automatically fixable Solhint issues
	@echo "Fixing linting issues in Solidity files..."
	@npx solhint $(SOL_FILES) --fix || yarn solhint $(SOL_FILES) --fix

slither: ## Run Slither security analysis
	@echo "Running Slither security analysis..."
	@slither . --config-file slither.config.json

gravity_verify:
	forge verify-contract --rpc-url https://rpc.gravity.xyz --verifier blockscout --verifier-url 'https://explorer-gravity-mainnet-0.t.conduit.xyz/api/' $(ADDRESS) src/VestingEarndrop/VestingEarndrop.sol:VestingEarndrop