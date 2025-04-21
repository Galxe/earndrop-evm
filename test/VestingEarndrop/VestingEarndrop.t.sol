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

  function testActivateEarndropWithOverflowEarndropId() public {
    uint256 earndropId = type(uint256).max;
    address tokenAddress = address(0);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 10 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    bytes memory signature = "";

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "earndropId too large"));
    vestingEarndrop.activateEarndrop{value: totalAmount}(
      earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature
    );
  }

  function testActivateEarndropWithInvalidEarndropId() public {
    uint256 earndropId = 0;
    address tokenAddress = address(0);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 10 ether;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});
    bytes memory signature = "";
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "earndropId cannot be 0"));
    vestingEarndrop.activateEarndrop{value: totalAmount}(
      earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature
    );
  }

  function testActivateEarndropWithInvalidTotalAmount() public {
    uint256 earndropId = 1;
    address tokenAddress = address(0);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 0;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});
    bytes memory signature = "";
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "totalAmount cannot be 0"));
    vestingEarndrop.activateEarndrop{value: totalAmount}(
      earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature
    );
  }

  function testActivateEarndropWithInvalidStageLength() public {
    uint256 earndropId = 1;
    address tokenAddress = address(0);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](0);
    // stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});
    bytes memory signature = "";
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "stages cannot be empty"));
    vestingEarndrop.activateEarndrop{value: totalAmount}(
      earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature
    );
  }

  function testActivateEarndropWithInvalidStageStartTime1() public {
    uint256 earndropId = 1;
    address tokenAddress = address(0);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp});
    bytes memory signature = "";
    vm.expectRevert(
      abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Stage startTime must be less than endTime")
    );
    vestingEarndrop.activateEarndrop{value: totalAmount}(
      earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature
    );
  }

  function testActivateEarndropWithInvalidStageStartTime2() public {
    uint256 earndropId = 1;
    address tokenAddress = address(0);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp, endTime: block.timestamp + 100});
    bytes memory signature = "";
    vm.expectRevert(
      abi.encodeWithSelector(
        VestingEarndrop.InvalidParameter.selector, "Stage startTime must be greater than current time"
      )
    );
    vestingEarndrop.activateEarndrop{value: totalAmount}(
      earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature
    );
  }

  function testActivateEarndropWithInvalidSignature() public {
    uint256 earndropId = 1;
    address tokenAddress = address(0);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;
    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    address invalidAddress = makeAddr("invalidAddress");

    bytes32 messageHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, invalidAddress);

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Invalid signature"));
    vestingEarndrop.activateEarndrop{value: totalAmount}(
      earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature
    );
  }

  function testActivateEarndropWithInvalidMsgValue() public {
    uint256 earndropId = 1;
    address tokenAddress = address(0);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    uint256 invalidMsgValue = 2;
    bytes32 messageHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Invalid amount"));
    vestingEarndrop.activateEarndrop{value: invalidMsgValue}(
      earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature
    );
  }

  function testActivateEarndropWithInsufficientAllowance() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount / 2);

    bytes32 messageHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectRevert();
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature);
  }

  function testActivateEarndropWithInsufficientBalance() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    // token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount / 2);

    bytes32 messageHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectRevert();
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature);
  }

  function testSuccessActivateEarndrop() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount);

    bytes32 messageHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectEmit(true, true, true, true);
    emit VestingEarndrop.EarndropActivated(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));

    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature);
  }

  function testActivateExistsEarndropId() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount);

    bytes32 messageHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectEmit(true, true, true, true);
    emit VestingEarndrop.EarndropActivated(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature);

    vm.expectRevert(abi.encodeWithSelector(EarndropAlreadyExists.selector));
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature);
  }

  function testActivateExistsEarndropStageId() public {
    uint256 earndropId1 = 1;
    address tokenAddress = address(token);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount);

    bytes32 messageHash =
      _hashEarndropActivate(earndropId1, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectEmit(true, true, true, true);
    emit VestingEarndrop.EarndropActivated(
      earndropId1, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this)
    );
    vestingEarndrop.activateEarndrop(earndropId1, tokenAddress, merkleTreeRoot, totalAmount, stages, signature);

    uint256 earndropId2 = 2;
    VestingEarndrop.Stage[] memory stages2 = new VestingEarndrop.Stage[](1);
    stages2[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount);

    bytes32 messageHash2 =
      _hashEarndropActivate(earndropId2, tokenAddress, merkleTreeRoot, totalAmount, stages2, address(this));

    (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(signerKey, messageHash2);
    bytes memory signature2 = abi.encodePacked(r2, s2, v2);

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Duplicate stageId found"));
    vestingEarndrop.activateEarndrop(earndropId2, tokenAddress, merkleTreeRoot, totalAmount, stages2, signature2);
  }

  function testRevokeNotExistsEarndrop() public {
    uint256 earndropId = 2000;
    address recipient = makeAddr("recipient");

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop does not exist"));

    vestingEarndrop.revokeEarndrop(earndropId, recipient);
  }

  function testRevokeAlreadyRevokedEarndrop() public {
    uint256 earndropId = 404;
    address tokenAddress = address(token);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount);

    bytes32 messageHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectEmit(true, true, true, true);
    emit VestingEarndrop.EarndropActivated(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));

    // activate earndrop
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature);

    // revoke earndrop
    address recipient = makeAddr("recipient");
    vestingEarndrop.revokeEarndrop(earndropId, recipient);

    // try to revoke again
    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop already revoked"));
    vestingEarndrop.revokeEarndrop(earndropId, recipient);
  }

  function testRevokeEarndropWithoutAdminPermission() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount);

    bytes32 activationHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, activationHash);
    bytes memory activationSignature = abi.encodePacked(r, s, v);

    // Activate the earndrop
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, activationSignature);

    // Simulate a different msg.sender (not the admin)
    address unauthorizedUser = makeAddr("unauthorizedUser");
    vm.prank(unauthorizedUser);

    // Attempt to revoke the earndrop
    vm.expectRevert(VestingEarndrop.Unauthorized.selector);
    vestingEarndrop.revokeEarndrop(earndropId, unauthorizedUser);
  }

  function testSuccessRevokeEarndrop() public {
    uint256 earndropId = 404;
    address tokenAddress = address(token);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount);

    bytes32 messageHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, messageHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectEmit(true, true, true, true);
    emit VestingEarndrop.EarndropActivated(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));

    // activate earndrop
    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, signature);

    // revoke earndrop
    address recipient = makeAddr("recipient");
    vestingEarndrop.revokeEarndrop(earndropId, recipient);

    (,, bool isRevoked,,,,) = vestingEarndrop.earndrops(earndropId);
    assertEq(isRevoked, true);
    assertEq(token.balanceOf(recipient), totalAmount);
  }

  function testClaimEarndropSuccessAndAlreadyClaimed() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount);

    uint256 stageId = 1;
    uint256 leafIndex = 0;
    uint256 claimAmount = 0.5 ether;
    (bytes32 merkleTreeRoot, bytes32[] memory merkleProof) =
      _generateMerkleTreeAndProof(earndropId, stageId, leafIndex, address(this), claimAmount);

    bytes32 activationHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, activationHash);
    bytes memory activationSignature = abi.encodePacked(r, s, v);

    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, activationSignature);

    vm.warp(block.timestamp + 3700);

    bytes32 claimHash = _hashEarndropClaim(earndropId, leafIndex, 0);
    (v, r, s) = vm.sign(signerKey, claimHash);
    bytes memory claimSignature = abi.encodePacked(r, s, v);

    vestingEarndrop.claimEarndrop(
      earndropId,
      VestingEarndrop.ClaimParams({
        stageId: stageId,
        leafIndex: leafIndex,
        account: address(this),
        amount: claimAmount,
        merkleProof: merkleProof
      }),
      claimSignature
    );

    assertTrue(vestingEarndrop.isClaimed(earndropId, leafIndex));
    assertEq(token.balanceOf(address(this)), claimAmount);

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Already claimed"));
    vestingEarndrop.claimEarndrop(
      earndropId,
      VestingEarndrop.ClaimParams({
        stageId: stageId,
        leafIndex: leafIndex,
        account: address(this),
        amount: claimAmount,
        merkleProof: merkleProof
      }),
      claimSignature
    );
  }

  function testClaimEarndropNonExistentEarndrop() public {
    uint256 earndropId = 999;
    uint256 stageId = 1;
    uint256 leafIndex = 0;
    uint256 claimAmount = 0.5 ether;

    bytes32[] memory merkleProof = new bytes32[](0);
    bytes memory claimSignature = "";

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop does not exist"));
    vestingEarndrop.claimEarndrop(
      earndropId,
      VestingEarndrop.ClaimParams({
        stageId: stageId,
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
    address tokenAddress = address(token);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount);

    bytes32 activationHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, activationHash);
    bytes memory activationSignature = abi.encodePacked(r, s, v);

    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, activationSignature);

    vestingEarndrop.revokeEarndrop(earndropId, address(this));

    vm.warp(block.timestamp + 3700);

    uint256 stageId = 1;
    uint256 leafIndex = 0;
    uint256 claimAmount = 0.5 ether;

    bytes32[] memory merkleProof = new bytes32[](0);
    bytes memory claimSignature = "";

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Earndrop revoked"));
    vestingEarndrop.claimEarndrop(
      earndropId,
      VestingEarndrop.ClaimParams({
        stageId: stageId,
        leafIndex: leafIndex,
        account: address(this),
        amount: claimAmount,
        merkleProof: merkleProof
      }),
      claimSignature
    );
  }

  function testClaimEarndropInvalidMerkleProof() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    bytes32 merkleTreeRoot = keccak256(abi.encodePacked("merkleRoot"));
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount);

    bytes32 activationHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, activationHash);
    bytes memory activationSignature = abi.encodePacked(r, s, v);

    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, activationSignature);

    vm.warp(block.timestamp + 3700);

    uint256 stageId = 1;
    uint256 leafIndex = 0;
    uint256 claimAmount = 0.5 ether;

    bytes32[] memory invalidMerkleProof = new bytes32[](1);
    invalidMerkleProof[0] = keccak256(abi.encodePacked("invalid proof"));

    bytes32 claimHash = _hashEarndropClaim(earndropId, leafIndex, 0);
    (v, r, s) = vm.sign(signerKey, claimHash);
    bytes memory claimSignature = abi.encodePacked(r, s, v);

    vm.expectRevert(VestingEarndrop.InvalidProof.selector);
    vestingEarndrop.claimEarndrop(
      earndropId,
      VestingEarndrop.ClaimParams({
        stageId: stageId,
        leafIndex: leafIndex,
        account: address(this),
        amount: claimAmount,
        merkleProof: invalidMerkleProof
      }),
      claimSignature
    );
  }

  function testClaimEarndropInvalidSignature() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    uint256 totalAmount = 1 ether;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] = VestingEarndrop.Stage({stageId: 1, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount);

    uint256 claimFee = 2 ether;
    uint256 stageId = 1;
    uint256 leafIndex = 0;
    uint256 claimAmount = 0.5 ether;
    (bytes32 merkleTreeRoot, bytes32[] memory merkleProof) =
      _generateMerkleTreeAndProof(earndropId, stageId, leafIndex, address(this), claimAmount);

    bytes32 activationHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, activationHash);
    bytes memory activationSignature = abi.encodePacked(r, s, v);

    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, activationSignature);

    vm.warp(block.timestamp + 3700);

    bytes32 claimHash = _hashEarndropClaim(earndropId, leafIndex, 0);
    (v, r, s) = vm.sign(signerKey, claimHash);
    bytes memory invalidClaimSignature = abi.encodePacked(r, s, v);

    vm.expectRevert(abi.encodeWithSelector(VestingEarndrop.InvalidParameter.selector, "Invalid signature"));
    vestingEarndrop.claimEarndrop{value: claimFee}(
      earndropId,
      VestingEarndrop.ClaimParams({
        stageId: stageId,
        leafIndex: leafIndex,
        account: address(this),
        amount: claimAmount,
        merkleProof: merkleProof
      }),
      invalidClaimSignature
    );
  }

  function testMultiClaimEarndropSuccess() public {
    uint256 earndropId = 1;
    address tokenAddress = address(token);
    uint256 totalAmount = 3 ether;
    uint256 stageId = 1;

    VestingEarndrop.Stage[] memory stages = new VestingEarndrop.Stage[](1);
    stages[0] =
      VestingEarndrop.Stage({stageId: stageId, startTime: block.timestamp + 3600, endTime: block.timestamp + 7200});

    token.mint(address(this), totalAmount);
    token.approve(address(vestingEarndrop), totalAmount);

    uint256 leafIndex1 = 0;
    uint256 claimAmount1 = 1 ether;
    (bytes32 merkleTreeRoot, bytes32[] memory merkleProof1) =
      _generateMerkleTreeAndProof(earndropId, stageId, leafIndex1, address(this), claimAmount1);

    bytes32 activationHash =
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, address(this));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, activationHash);
    bytes memory activationSignature = abi.encodePacked(r, s, v);

    vestingEarndrop.activateEarndrop(earndropId, tokenAddress, merkleTreeRoot, totalAmount, stages, activationSignature);

    vm.warp(block.timestamp + 3700);

    VestingEarndrop.ClaimParams[] memory claimParams = new VestingEarndrop.ClaimParams[](1);

    claimParams[0] = VestingEarndrop.ClaimParams({
      stageId: stageId,
      leafIndex: leafIndex1,
      account: address(this),
      amount: claimAmount1,
      merkleProof: merkleProof1
    });

    uint256 claimFee = 0;
    bytes32 claimHash = _hashEarndropClaim(earndropId, claimParams[0].leafIndex, claimFee);
    (v, r, s) = vm.sign(signerKey, claimHash);
    bytes memory claimSignature = abi.encodePacked(r, s, v);

    vestingEarndrop.multiClaimEarndrop{value: claimFee}(earndropId, claimParams, claimSignature);

    assertTrue(vestingEarndrop.isClaimed(earndropId, leafIndex1));

    assertEq(token.balanceOf(address(this)), claimAmount1);
  }

  function _generateMerkleTreeAndProof(
    uint256 earndropId,
    uint256 stageId,
    uint256 leafIndex,
    address account,
    uint256 amount
  ) private pure returns (bytes32 merkleRoot, bytes32[] memory merkleProof) {
    bytes32[] memory leaves = new bytes32[](2);
    leaves[0] = keccak256(abi.encodePacked(earndropId, stageId, leafIndex, account, amount));
    leaves[1] = keccak256(abi.encodePacked(earndropId, stageId, leafIndex + 1, account, amount));

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
      hashes[i] = keccak256(abi.encode(_stagesArray[i].stageId, _stagesArray[i].startTime, _stagesArray[i].endTime));
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
