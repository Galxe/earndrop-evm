// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {VestingEarndrop} from "../../src/VestingEarndrop/VestingEarndrop.sol";

import {BaseScript} from "../utils/Base.s.sol";
import {Script, console} from "forge-std/Script.sol";

contract VestingEarndropScript is BaseScript {
  string internal constant KEY = "GALXE_VESTING_EARNDROP";

  function run() external chain broadcaster {
    bytes32 CREATE2_SALT = vm.envBytes32("CREATE2_SALT");
    address owner = vm.envAddress("OWNER");
    address signer = vm.envAddress("SIGNER");
    address treasurer = vm.envAddress("TREASURER");

    console.log("Owner:", owner);
    console.log("Signer:", signer);
    console.log("Treasurer:", treasurer);

    // vm.startBroadcast();

    VestingEarndrop vestingEarndrop = new VestingEarndrop{salt: CREATE2_SALT}(owner, signer, treasurer);
    // VestingEarndrop vestingEarndrop = new VestingEarndrop(owner, signer, treasurer);
    console.log("VestingEarndrop deployed at:", address(vestingEarndrop));

    writeAddress(KEY, address(vestingEarndrop));
  }
}
