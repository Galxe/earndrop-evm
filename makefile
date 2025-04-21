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

.PHONY: test coverage build_vesting


gravity_verify:
	forge verify-contract --rpc-url https://rpc.gravity.xyz --verifier blockscout --verifier-url 'https://explorer-gravity-mainnet-0.t.conduit.xyz/api/' $(ADDRESS) src/VestingEarndrop/VestingEarndrop.sol:VestingEarndrop



		