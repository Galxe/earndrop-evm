// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {VestingEarndrop} from "../../src/VestingEarndrop/VestingEarndrop.sol";

import {ERC20} from "@openzeppelin-v5/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin-v5/contracts/token/ERC20/IERC20.sol";
import {Test, console} from "forge-std/Test.sol";

contract MockERC20 is ERC20 {
  constructor() ERC20("Mock Token", "MOCK") {}

  function mint(address to, uint256 amount) external {
    _mint(to, amount);
  }
}

contract VestingEarndropTest is Test {
  VestingEarndrop public vestingEarndrop;
  MockERC20 public token;

  address public owner;
  uint256 public signerKey;
  address public signer;
  address public treasurer;

  bytes32 internal constant _TYPE_HASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
  bytes32 internal constant _HASHED_NAME = keccak256("Galxe Vesting Earndrop");
  bytes32 internal constant _HASHED_VERSION = keccak256("1.0.0");

  error InvalidAddress();
  error EarndropAlreadyExists();
  error InvalidParameter(string);
  error Unauthorized();
  error InvalidProof();
  error TransferFailed();

  function setUp() public {
    owner = makeAddr("owner");
    signerKey = 0x1234;
    signer = vm.addr(signerKey);
    treasurer = makeAddr("treasurer");

    vestingEarndrop = new VestingEarndrop(owner, signer, treasurer);
    token = new MockERC20();
  }

  function testConstructor() public view {
    assertEq(vestingEarndrop.owner(), owner);
    assertEq(vestingEarndrop.signer(), signer);
    assertEq(vestingEarndrop.treasurer(), treasurer);
  }

  function testSetSigner() public {
    address newSigner = makeAddr("newSigner");
    vm.prank(owner);
    vestingEarndrop.setSigner(newSigner);
    assertEq(vestingEarndrop.signer(), newSigner);
  }

  function testSetSignerInvalidAddress() public {
    vm.prank(owner);
    vm.expectRevert(VestingEarndrop.InvalidAddress.selector);
    vestingEarndrop.setSigner(address(0));
  }

  function testSetTreasurer() public {
    address newTreasurer = makeAddr("newTreasurer");
    vm.prank(owner);
    vestingEarndrop.setTreasurer(newTreasurer);
    assertEq(vestingEarndrop.treasurer(), newTreasurer);
  }

  function testSetTreasurerInvalidAddress() public {
    vm.prank(owner);
    vm.expectRevert(VestingEarndrop.InvalidAddress.selector);
    vestingEarndrop.setTreasurer(address(0));
  }

  function testSetEarndropRevocableNotExists() public {
    uint256 earndropId = 1;
    vm.prank(owner);
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop does not exist"));
    vestingEarndrop.setEarndropRevocable(earndropId, true);
  }

  function testSetEarndropRevocableSuccess() public {
    uint256 earndropId = 1;
    address admin = makeAddr("admin");
    _setupEarndrop(earndropId, admin, address(0));

    vm.prank(owner);
    vestingEarndrop.setEarndropRevocable(earndropId, true);

    (,,,,,,, bool revocable,) = vestingEarndrop.earndrops(earndropId);
    assertTrue(revocable, "Earndrop should be revocable");
  }

  function testtestSetEarndropRevocableAlreadyRevoked() public {
    uint256 earndropId = 1;
    address admin = makeAddr("admin");
    address recipient = makeAddr("recipient");
    uint256 totalAmount = 1 ether;
    _setupEarndrop(earndropId, admin, address(token));

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    vm.prank(owner);
    vestingEarndrop.setEarndropRevocable(earndropId, true);

    vm.prank(admin);
    vestingEarndrop.revokeEarndrop(earndropId, recipient);

    vm.prank(owner);
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop already revoked"));
    vestingEarndrop.setEarndropRevocable(earndropId, true);
  }

  function testTransferEarndropAdminSuccess() public {
    uint256 earndropId = 1;
    address newAdmin = makeAddr("newAdmin");

    _setupEarndrop(earndropId, address(this), address(0));

    vestingEarndrop.transferEarndropAdmin(earndropId, newAdmin);

    (,,,, address admin,,,,) = vestingEarndrop.earndrops(earndropId);
    assertEq(admin, newAdmin);
  }

  function testTransferEarndropAdminNotExists() public {
    uint256 earndropId = 404;
    address newAdmin = makeAddr("newAdmin");

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop does not exist"));
    vestingEarndrop.transferEarndropAdmin(earndropId, newAdmin);
  }

  function testTransferEarndropAdminUnauthorized() public {
    uint256 earndropId = 1;
    address newAdmin = makeAddr("newAdmin");

    _setupEarndrop(earndropId, address(this), address(0));

    vm.prank(makeAddr("unauthorized"));
    vm.expectRevert(VestingEarndrop.Unauthorized.selector);
    vestingEarndrop.transferEarndropAdmin(earndropId, newAdmin);
  }

  function testTransferEarndropAdminInvalidAddress() public {
    uint256 earndropId = 1;

    _setupEarndrop(earndropId, address(this), address(0));

    vm.expectRevert(
      abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "New admin cannot be the zero address")
    );
    vestingEarndrop.transferEarndropAdmin(earndropId, address(0));
  }

  function testActivateEarndropWithOverflowEarndropId() public {
    uint256 earndropId = type(uint256).max;
    address tokenAddress = address(0);
    address admin = makeAddr("admin");
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 10 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] =
      VestingEarndrop.Stage({startTime: uint8(block.timestamp + 3600), endTime: uint48(block.timestamp + 7200)});

    bytes memory signature = "";

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "earndropId too large"));
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, admin, merkleTreeRoot, totalAmount, stages, signature);
  }

  function testActivateEarndropWithInvalidEarndropId() public {
    uint256 earndropId = 0;
    address tokenAddress = address(0);
    address admin = makeAddr("admin");
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 10 ether;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] =
      VestingEarndrop.Stage({startTime: uint48(block.timestamp + 3600), endTime: uint48(block.timestamp + 7200)});
    bytes memory signature = "";
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "earndropId cannot be 0"));
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, admin, merkleTreeRoot, totalAmount, stages, signature);
  }

  function testActivateEarndropWithInvalidTotalAmount() public {
    uint256 earndropId = 1;
    address tokenAddress = address(0);
    address admin = makeAddr("admin");
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 0;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] =
      VestingEarndrop.Stage({startTime: uint48(block.timestamp + 3600), endTime: uint48(block.timestamp + 7200)});
    bytes memory signature = "";
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "totalAmount cannot be 0"));
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, admin, merkleTreeRoot, totalAmount, stages, signature);
  }

  function testActivateEarndropWithInvalidStageLength() public {
    uint256 earndropId = 1;
    address tokenAddress = address(0);
    address admin = makeAddr("admin");
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](0);
    // stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: uint48(block.timestamp + 3600), endTime: uint48(block.timestamp + 7200)});
    bytes memory signature = "";
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Stages cannot be empty"));
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, admin, merkleTreeRoot, totalAmount, stages, signature);
  }

  function testActivateEarndropWithInvalidStageStartTime1() public {
    uint256 earndropId = 1;
    address tokenAddress = address(0);
    address admin = makeAddr("admin");
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({startTime: uint48(block.timestamp + 3600), endTime: uint48(block.timestamp)});
    bytes memory signature = "";
    vm.expectRevert(
      abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Stage startTime must be less than endTime")
    );
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, admin, merkleTreeRoot, totalAmount, stages, signature);
  }

  function testActivateEarndropWithInvalidStageStartTime2() public {
    uint256 earndropId = 1;
    address tokenAddress = address(0);
    address admin = makeAddr("admin");
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({startTime: uint48(block.timestamp), endTime: uint48(block.timestamp + 100)});
    bytes memory signature = "";
    vm.expectRevert(
      abi.encodeWithSelector(
        VestingEarndrop.InvalidParameter.selector, "Stage startTime must be greater than current time"
      )
    );
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, admin, merkleTreeRoot, totalAmount, stages, signature);
  }

  function testActivateEarndropWithInvalidStageStartTime3() public {
    uint256 earndropId = 1;
    address tokenAddress = address(0);
    address admin = makeAddr("admin");
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](2);
    stages[0] = VestingEarndrop.Stage({startTime: uint48(block.timestamp + 50), endTime: uint48(block.timestamp + 100)});
    stages[1] = VestingEarndrop.Stage({startTime: uint48(block.timestamp + 20), endTime: uint48(block.timestamp + 100)});
    bytes memory signature = "";
    vm.expectRevert(
      abi.encodeWithSelector(
        VestingEarndrop.InvalidParameter.selector, "Stages must be sorted by startTime in ascending order"
      )
    );
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, admin, merkleTreeRoot, totalAmount, stages, signature);
  }

  function testActivateEarndropWithInvalidSignature() public {
    uint256 earndropId = 1;
    address tokenAddress = address(0);
    address admin = makeAddr("admin");
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] =
      VestingEarndrop.Stage({startTime: uint48(block.timestamp + 3600), endTime: uint48(block.timestamp + 7200)});

    address invalidAddress = makeAddr("invalidAddress");

    bytes32 messageHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, invalidAddress);

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Invalid signature"));
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, admin, merkleTreeRoot, totalAmount, stages, signature);
  }

  function testSuccessActivateEarndrop() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    address admin = makeAddr("admin");
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] =
      VestingEarndrop.Stage({startTime: uint48(block.timestamp + 3600), endTime: uint48(block.timestamp + 7200)});

    bytes32 messageHash = _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, admin);

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectEmit(true, true, true, true);
    emit VestingEarndrop.EarndropActivated(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, admin);

    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, admin, merkleTreeRoot, totalAmount, stages, signature);

    (,,,, address earndropAdmin,,,,) = vestingEarndrop.earndrops(earndropId);
    assertEq(earndropAdmin, admin);

    VestingEarndrop.Stage[] memory earndropStages = vestingEarndrop.getEarndropStages(earndropId);
    assertEq(earndropStages.length, stages.length, "Stages length mismatch");
    for (uint256 i = 0; i < stages.length; i++) {
      assertEq(earndropStages[i].startTime, stages[i].startTime, "Stage startTime mismatch");
      assertEq(earndropStages[i].endTime, stages[i].endTime, "Stage endTime mismatch");
    }
  }

  function testActivateExistsEarndropId() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    address admin = makeAddr("admin");
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    bytes memory signature = "";

    _setupEarndrop(earndropId, admin, address(0));

    vm.expectRevert(abi.encodeWithSelector(EarndropAlreadyExists.selector));
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, admin, merkleTreeRoot, totalAmount, stages, signature);
  }

  function testConfirmActivateEarndropSuccess() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    address admin = makeAddr("admin");
    uint256 totalAmount = 1 ether;

    _setupEarndrop(earndropId, admin, tokenAddress);

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    (,,,,,,,, bool confirmed) = vestingEarndrop.earndrops(earndropId);
    assertTrue(confirmed, "Earndrop should be confirmed");
    assertEq(token.balanceOf(address(vestingEarndrop)), totalAmount, "Contract should hold the total amount of tokens");
  }

  function testConfirmActivateEarndropNotExists() public {
    uint256 earndropId = 404;
    address admin = makeAddr("admin");

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop does not exist"));
    vestingEarndrop.confirmActivateEarndrop(earndropId);
  }

  function testConfirmActivateEarndropRevoked() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    address admin = makeAddr("admin");
    address recipient = makeAddr("recipient");
    uint256 totalAmount = 1 ether;

    _setupEarndrop(earndropId, admin, tokenAddress);

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    vm.prank(owner);
    vestingEarndrop.setEarndropRevocable(earndropId, true);

    vm.prank(admin);
    vestingEarndrop.revokeEarndrop(earndropId, recipient);

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop already revoked"));
    vestingEarndrop.confirmActivateEarndrop(earndropId);
  }

  function testConfirmActivateEarndropConfirmed() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    address admin = makeAddr("admin");
    uint256 totalAmount = 1 ether;

    _setupEarndrop(earndropId, admin, tokenAddress);

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop already confirmed"));
    vestingEarndrop.confirmActivateEarndrop(earndropId);
  }

  function testConfirmActivateEarndropUnauthorized() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    address admin = makeAddr("admin");

    _setupEarndrop(earndropId, admin, tokenAddress);

    address unauthorized = makeAddr("unauthorized");
    vm.prank(unauthorized);
    vm.expectRevert(VestingEarndrop.Unauthorized.selector);
    vestingEarndrop.confirmActivateEarndrop(earndropId);
  }

  function testConfirmActivateEarndropInvalidMsgValue1() public {
    uint256 earndropId = 1;
    address tokenAddress = address(0);
    address admin = makeAddr("admin");

    _setupEarndrop(earndropId, admin, tokenAddress);

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Invalid amount"));
    vestingEarndrop.confirmActivateEarndrop(earndropId);
  }

  function testConfirmActivateEarndropInsufficientAllowance() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    address admin = makeAddr("admin");

    _setupEarndrop(earndropId, admin, tokenAddress);

    vm.prank(admin);
    vm.expectRevert();
    vestingEarndrop.confirmActivateEarndrop(earndropId);
  }

  function testConfirmActivateEarndropInsufficientBalance() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    address admin = makeAddr("admin");
    uint256 totalAmount = 1 ether;

    _setupEarndrop(earndropId, admin, tokenAddress);

    token.mint(admin, totalAmount);

    vm.expectRevert();
    vestingEarndrop.confirmActivateEarndrop(earndropId);
  }

  function testRevokeEarndropAllStagesEnded() public {
    uint256 earndropId = 1;
    address admin = makeAddr("admin");
    address recipient = makeAddr("recipient");
    uint256 totalAmount = 1 ether;

    _setupEarndrop(earndropId, admin, address(token));

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    vm.warp(block.timestamp + 7201);

    vm.prank(admin);
    vestingEarndrop.revokeEarndrop(earndropId, recipient);

    (,,,,,, bool revoked,,) = vestingEarndrop.earndrops(earndropId);
    assertTrue(revoked, "Earndrop should be revoked");
    assertEq(token.balanceOf(recipient), totalAmount, "Recipient should receive the remaining tokens");
  }

  function testRevokeEarndropStagesNotEndedAndNotRevocable() public {
    uint256 earndropId = 1;
    address admin = makeAddr("admin");
    address recipient = makeAddr("recipient");
    uint256 totalAmount = 1 ether;

    _setupEarndrop(earndropId, admin, address(token));

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    vm.warp(uint48(block.timestamp + 3600));

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop is not revocable"));
    vestingEarndrop.revokeEarndrop(earndropId, recipient);
  }

  function testRevokeEarndropSuccess() public {
    uint256 earndropId = 1;
    uint256 totalAmount = 1 ether;
    address admin = makeAddr("admin");
    address recipient = makeAddr("recipient");
    address tokenAddress = address(token);

    _setupEarndrop(earndropId, admin, tokenAddress);

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    vm.prank(owner);
    vestingEarndrop.setEarndropRevocable(earndropId, true);

    vm.prank(admin);

    vestingEarndrop.revokeEarndrop(earndropId, recipient);

    (,,,,,, bool revoked,,) = vestingEarndrop.earndrops(earndropId);
    assertTrue(revoked, "Earndrop should be revoked");
  }

  function testRevokeNotExistsEarndrop() public {
    uint256 earndropId = 404;
    address recipient = makeAddr("recipient");

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop does not exist"));
    vestingEarndrop.revokeEarndrop(earndropId, recipient);
  }

  function testRevokeEarndropAlreadyRevoked() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    address admin = makeAddr("admin");
    address recipient = makeAddr("recipient");
    uint256 totalAmount = 1 ether;

    _setupEarndrop(earndropId, admin, tokenAddress);

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    vm.prank(owner);
    vestingEarndrop.setEarndropRevocable(earndropId, true);

    vm.prank(admin);
    vestingEarndrop.revokeEarndrop(earndropId, recipient);

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop already revoked"));
    vestingEarndrop.revokeEarndrop(earndropId, recipient);
  }

  function testRevokeEarndropNotConfirmed() public {
    uint256 earndropId = 1;
    address admin = makeAddr("admin");
    address recipient = makeAddr("recipient");

    _setupEarndrop(earndropId, admin, address(token));

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop not confirmed"));
    vestingEarndrop.revokeEarndrop(earndropId, recipient);
  }

  function testRevokeEarndropNotRevocable() public {
    uint256 earndropId = 1;
    address admin = makeAddr("admin");
    address recipient = makeAddr("recipient");
    uint256 totalAmount = 1 ether;

    _setupEarndrop(earndropId, admin, address(token));

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    vm.prank(admin);
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop is not revocable"));
    vestingEarndrop.revokeEarndrop(earndropId, recipient);
  }

  function testRevokeEarndropUnauthorized() public {
    uint256 earndropId = 1;
    address admin = makeAddr("admin");
    address unauthorized = makeAddr("unauthorized");
    address recipient = makeAddr("recipient");
    uint256 totalAmount = 1 ether;

    _setupEarndrop(earndropId, admin, address(token));

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    vm.prank(owner);
    vestingEarndrop.setEarndropRevocable(earndropId, true);

    vm.prank(unauthorized);
    vm.expectRevert(VestingEarndrop.Unauthorized.selector);
    vestingEarndrop.revokeEarndrop(earndropId, recipient);
  }

  function testRevokeEarndropInvalidRecipient() public {
    uint256 earndropId = 1;
    address admin = makeAddr("admin");
    address recipient = address(0);
    uint256 totalAmount = 1 ether;

    _setupEarndrop(earndropId, admin, address(token));

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    vm.prank(owner);
    vestingEarndrop.setEarndropRevocable(earndropId, true);

    vm.prank(admin);
    vm.expectRevert(
      abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Recipient cannot be the zero address")
    );
    vestingEarndrop.revokeEarndrop(earndropId, recipient);
  }

  function testMultiClaimEarndropSuccess() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    uint256 totalAmount = 3 ether;
    uint256 stageIndex = 0;
    address admin = makeAddr("admin");
    address claimer = address(this);
    vm.deal(claimer, 1 ether);

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] =
      VestingEarndrop.Stage({startTime: uint48(block.timestamp + 3600), endTime: uint48(block.timestamp + 7200)});

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    uint256 leafIndex1 = 1;
    uint256 claimAmount1 = 1 ether;
    (bytes32 merkleTreeRoot, bytes32[] memory merkleProof1) =
      _generateMerkleTreeAndProof(earndropId, stageIndex, leafIndex1, claimer, claimAmount1);

    bytes32 activationHash = _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, admin);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, activationHash);
    bytes memory activationSignature = abi.encodePacked(r, s, v);

    vestingEarndrop.activateEarndrop(
      earndropId, tokenAddress, admin, merkleTreeRoot, totalAmount, stages, activationSignature
    );

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    vm.warp(block.timestamp + 3700);

    VestingEarndrop.ClaimParams[] memory claimParams = new VestingEarndrop.ClaimParams[](1);

    claimParams[0] = VestingEarndrop.ClaimParams({
      stageIndex: stageIndex,
      leafIndex: leafIndex1,
      account: claimer,
      amount: claimAmount1,
      merkleProof: merkleProof1
    });

    uint256 claimFee = 0;
    bytes32 claimHash = _hashEarndropClaim(earndropId, claimParams[0].leafIndex, claimFee);
    (v, r, s) = vm.sign(signerKey, claimHash);
    bytes memory claimSignature = abi.encodePacked(r, s, v);

    vestingEarndrop.multiClaimEarndrop{value: claimFee}(earndropId, claimParams, claimSignature);

    assertTrue(vestingEarndrop.isClaimed(earndropId, leafIndex1));

    assertEq(token.balanceOf(claimer), claimAmount1);
  }

  function testClaimEarndropNonExistentEarndrop() public {
    uint256 earndropId = 999;
    uint256 stageIndex = 1;
    uint256 leafIndex = 0;
    uint256 claimAmount = 0.5 ether;

    bytes32[] memory merkleProof = new bytes32[](0);
    bytes memory claimSignature = "";

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop does not exist"));
    vestingEarndrop.claimEarndrop(
      earndropId,
      VestingEarndrop.ClaimParams({
        stageIndex: stageIndex,
        leafIndex: leafIndex,
        account: address(this),
        amount: claimAmount,
        merkleProof: merkleProof
      }),
      claimSignature
    );
  }

  function testClaimEarndropNoConfirmed() public {
    uint256 earndropId = 1;
    address admin = makeAddr("admin");
    uint256 claimAmount = 0.5 ether;
    uint256 stageIndex = 1;
    uint256 leafIndex = 0;

    _setupEarndrop(earndropId, admin, address(token));

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop not confirmed"));
    bytes32[] memory merkleProof = new bytes32[](0);
    bytes memory claimSignature = "";
    vestingEarndrop.claimEarndrop(
      earndropId,
      VestingEarndrop.ClaimParams({
        stageIndex: stageIndex,
        leafIndex: leafIndex,
        account: address(this),
        amount: claimAmount,
        merkleProof: merkleProof
      }),
      claimSignature
    );
  }

  function testClaimEarndropRevoked() public {
    uint256 earndropId = 1;
    address admin = makeAddr("admin");
    uint256 totalAmount = 1 ether;
    uint256 claimAmount = 0.5 ether;
    uint256 stageIndex = 1;
    uint256 leafIndex = 0;
    address recipient = makeAddr("recipient");

    _setupEarndrop(earndropId, admin, address(token));

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    vm.prank(owner);
    vestingEarndrop.setEarndropRevocable(earndropId, true);

    vm.prank(admin);
    vestingEarndrop.revokeEarndrop(earndropId, recipient);

    bytes32[] memory merkleProof = new bytes32[](0);
    bytes memory claimSignature = "";
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop already revoked"));
    vestingEarndrop.claimEarndrop(
      earndropId,
      VestingEarndrop.ClaimParams({
        stageIndex: stageIndex,
        leafIndex: leafIndex,
        account: address(this),
        amount: claimAmount,
        merkleProof: merkleProof
      }),
      claimSignature
    );
  }

  function testClaimEarndropStageNotExists() public {
    uint256 earndropId = 1;
    address admin = makeAddr("admin");
    uint256 totalAmount = 1 ether;
    uint256 claimAmount = 0.5 ether;
    uint256 leafIndex = 0;

    _setupEarndrop(earndropId, admin, address(token));

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    bytes32[] memory merkleProof = new bytes32[](0);
    bytes memory claimSignature = "";
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Invalid stage index"));
    vestingEarndrop.claimEarndrop(
      earndropId,
      VestingEarndrop.ClaimParams({
        stageIndex: 404,
        leafIndex: leafIndex,
        account: address(this),
        amount: claimAmount,
        merkleProof: merkleProof
      }),
      claimSignature
    );
  }

  function testClaimEarndropStageNotStart() public {
    uint256 earndropId = 1;
    address admin = makeAddr("admin");
    uint256 totalAmount = 1 ether;
    uint256 claimAmount = 0.5 ether;
    uint256 stageIndex = 0;
    uint256 leafIndex = 0;

    _setupEarndrop(earndropId, admin, address(token));

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    bytes32[] memory merkleProof = new bytes32[](0);
    bytes memory claimSignature = "";
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Stage not started yet"));
    vestingEarndrop.claimEarndrop(
      earndropId,
      VestingEarndrop.ClaimParams({
        stageIndex: stageIndex,
        leafIndex: leafIndex,
        account: address(this),
        amount: claimAmount,
        merkleProof: merkleProof
      }),
      claimSignature
    );
  }

  function testClaimEarndropStageEnded() public {
    uint256 earndropId = 1;
    address admin = makeAddr("admin");
    uint256 totalAmount = 1 ether;
    uint256 claimAmount = 0.5 ether;
    uint256 stageIndex = 0;
    uint256 leafIndex = 0;

    _setupEarndrop(earndropId, admin, address(token));

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    bytes32[] memory merkleProof = new bytes32[](0);
    bytes memory claimSignature = "";

    vm.warp(block.timestamp + 9200);

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Stage ended"));
    vestingEarndrop.claimEarndrop(
      earndropId,
      VestingEarndrop.ClaimParams({
        stageIndex: stageIndex,
        leafIndex: leafIndex,
        account: address(this),
        amount: claimAmount,
        merkleProof: merkleProof
      }),
      claimSignature
    );
  }

  function testClaimEarndropInvalidSignature() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    uint256 totalAmount = 3 ether;
    uint256 stageIndex = 0;
    address admin = makeAddr("admin");
    address claimer = address(this);
    vm.deal(claimer, 1 ether);

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] =
      VestingEarndrop.Stage({startTime: uint48(block.timestamp + 3600), endTime: uint48(block.timestamp + 7200)});

    token.mint(admin, totalAmount);
    vm.prank(admin);
    token.approve(address(vestingEarndrop), totalAmount);

    uint256 leafIndex1 = 0;
    uint256 claimAmount1 = 1 ether;
    (bytes32 merkleTreeRoot, bytes32[] memory merkleProof1) =
      _generateMerkleTreeAndProof(earndropId, stageIndex, leafIndex1, claimer, claimAmount1);

    bytes32 activationHash = _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, admin);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, activationHash);
    bytes memory activationSignature = abi.encodePacked(r, s, v);

    vestingEarndrop.activateEarndrop(
      earndropId, tokenAddress, admin, merkleTreeRoot, totalAmount, stages, activationSignature
    );

    vm.prank(admin);
    vestingEarndrop.confirmActivateEarndrop(earndropId);

    vm.warp(block.timestamp + 3700);

    uint256 claimFee = 0;

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Invalid signature"));

    vestingEarndrop.claimEarndrop{value: claimFee}(
      earndropId,
      VestingEarndrop.ClaimParams({
        stageIndex: stageIndex,
        leafIndex: leafIndex1,
        account: claimer,
        amount: claimAmount1,
        merkleProof: merkleProof1
      }),
      activationSignature // invalid signature
    );
  }

  function _setupEarndrop(uint256 earndropId, address admin, address _token) private {
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] =
      VestingEarndrop.Stage({startTime: uint48(block.timestamp + 3600), endTime: uint48(block.timestamp + 7200)});

    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;

    bytes32 messageHash = _hashEarndropActivate(earndropId, _token, merkleTreeRoot, totalAmount, stages, admin);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.prank(admin);
    vestingEarndrop.activateEarndrop(earndropId, _token, admin, merkleTreeRoot, totalAmount, stages, signature);
  }

  function _generateMerkleTreeAndProof(
    uint256 earndropId,
    uint256 stageIndex,
    uint256 leafIndex,
    address account,
    uint256 amount
  ) private pure returns (bytes32 merkleRoot, bytes32[] memory merkleProof) {
    bytes32[] memory leaves = new bytes32[](2);
    leaves[0] = keccak256(abi.encodePacked(earndropId, stageIndex, leafIndex, account, amount));
    leaves[1] = keccak256(abi.encodePacked(earndropId, stageIndex, leafIndex + 1, account, amount));

    merkleRoot = keccak256(abi.encodePacked(leaves[0], leaves[1]));

    merkleProof = new bytes32[](1);
    merkleProof[0] = leaves[1];
  }

  function _hashEarndropActivate(
    uint256 earndropId,
    address tokenAddress,
    bytes32 merkleTreeRoot,
    uint256 totalAmount,
    VestingEarndrop.Stage[] memory _stagesArray,
    address _admin
  ) private view returns (bytes32) {
    bytes32 stagesHash = _hashStages(_stagesArray);
    return _hashTypedDataV4(
      keccak256(
        abi.encode(
          keccak256(
            "Earndrop(uint256 earndropId,address tokenAddress,bytes32 merkleTreeRoot,uint256 totalAmount,bytes32[] stagesArray,address admin)"
          ),
          earndropId,
          tokenAddress,
          merkleTreeRoot,
          totalAmount,
          stagesHash,
          _admin
        )
      )
    );
  }

  function _hashStages(VestingEarndrop.Stage[] memory _stagesArray) private pure returns (bytes32) {
    bytes32[] memory hashes = new bytes32[](_stagesArray.length);
    for (uint256 i = 0; i < _stagesArray.length; i++) {
      hashes[i] = keccak256(abi.encode(_stagesArray[i].startTime, _stagesArray[i].endTime));
    }
    return keccak256(abi.encodePacked(hashes));
  }

  function _hashEarndropClaim(uint256 earndropId, uint256 leafIndex, uint256 value) private view returns (bytes32) {
    return _hashTypedDataV4(
      keccak256(
        abi.encode(
          keccak256("EarndropClaim(uint256 earndropId,uint256 leafIndex,uint256 value)"), earndropId, leafIndex, value
        )
      )
    );
  }

  // --------------- EIP712 signature tools ------------- //
  function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
    return keccak256(abi.encodePacked("\x19\x01", _buildDomainSeparator(), structHash));
  }

  function _buildDomainSeparator() private view returns (bytes32) {
    return keccak256(abi.encode(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION, _getChainId(), address(vestingEarndrop)));
  }

  function _getChainId() private view returns (uint256 chainId) {
    this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
    // solhint-disable-next-line no-inline-assembly
    assembly {
      chainId := chainid()
    }
  }
}
