// SPDX-License-Identifier: Apache-2.0

/*
     Copyright 2024 Galxe.

     Licensed under the Apache License, Version 2.0 (the "License");
     you may not use this file except in compliance with the License.
     You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

     Unless required by applicable law or agreed to in writing, software
     distributed under the License is distributed on an "AS IS" BASIS,
     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     See the License for the specific language governing permissions and
     limitations under the License.
 */
pragma solidity ^0.8.24;

import "@openzeppelin-v5/contracts/access/Ownable2Step.sol";
import "@openzeppelin-v5/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin-v5/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin-v5/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin-v5/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin-v5/contracts/utils/cryptography/MerkleProof.sol";

contract VestingEarndrop is Ownable2Step, EIP712 {
  using SafeERC20 for IERC20;

  error InvalidAddress();
  error EarndropAlreadyExists();
  error InvalidParameter(string msg);
  error Unauthorized();
  error InvalidProof();
  error TransferFailed();

  struct Stage {
    uint256 stageId;
    uint256 startTime;
    uint256 endTime;
  }

  struct Earndrop {
    address tokenAddress;
    uint96 earndropId;
    bool revoked;
    bool pendingRevoke;
    bool confirmed;
    bytes32 merkleTreeRoot;
    uint256 totalAmount;
    uint256 claimedAmount;
    mapping(uint256 => Stage) stages;
    address admin;
  }

  struct ClaimParams {
    uint256 stageId;
    uint256 leafIndex;
    address account;
    uint256 amount;
    bytes32[] merkleProof;
  }

  address public signer;
  address public treasurer;
  mapping(uint256 => Earndrop) public earndrops;
  mapping(uint256 => mapping(uint256 => bool)) private claimed;

  event EarndropActivated(
    uint256 earndropId, address tokenAddress, bytes32 merkleTreeRoot, uint256 totalAmount, Stage[] stages, address admin
  );
  event EarndropConfirmed(uint256 earndropId, address admin, uint256 totalAmount);
  event EarndropRevokeRequested(uint256 earndropId, address admin);
  event EarndropRevoked(uint256 earndropId, address recipient, uint256 remainingAmount);
  event EarndropRevokeCancelled(uint256 earndropId, address admin);
  event EarndropClaimed(
    uint256 indexed earndropId,
    uint256 indexed stageId,
    uint256 leafIndex,
    address account,
    uint256 amount,
    uint256 value
  );
  event EarndropAdminTransferred(uint256 earndropId, address indexed previousAdmin, address indexed newAdmin);

  constructor(address _owner, address _signer, address _treasurer)
    Ownable(_owner)
    EIP712("Galxe Vesting Earndrop", "1.0.0")
  {
    if (_signer == address(0) || _treasurer == address(0)) {
      revert InvalidAddress();
    }
    signer = _signer;
    treasurer = _treasurer;
  }

  function setSigner(address _signer) external onlyOwner {
    if (_signer == address(0)) {
      revert InvalidAddress();
    }
    signer = _signer;
  }

  function setTreasurer(address _treasurer) external onlyOwner {
    if (_treasurer == address(0)) {
      revert InvalidAddress();
    }
    treasurer = _treasurer;
  }

  /**
   * @dev Activates a new Earndrop.
   * @param earndropId The unique ID of the Earndrop.
   * @param tokenAddress The address of the token to be distributed.
   * @param admin The admin address responsible for managing the Earndrop.
   * @param merkleTreeRoot The Merkle tree root for claim verification.
   * @param totalAmount The total amount of tokens for the Earndrop.
   * @param _stagesArray The array of stages for the Earndrop.
   * @param _signature The signature for activation verification.
   */
  function activateEarndrop(
    uint256 earndropId,
    address tokenAddress,
    address admin,
    bytes32 merkleTreeRoot,
    uint256 totalAmount,
    Stage[] calldata _stagesArray,
    bytes calldata _signature
  ) external {
    if (earndropId > type(uint96).max) {
      revert InvalidParameter("earndropId too large");
    }

    Earndrop storage earndrop = earndrops[earndropId];
    if (earndrop.earndropId != 0) {
      revert EarndropAlreadyExists();
    }

    if (earndropId == 0) {
      revert InvalidParameter("earndropId cannot be 0");
    }

    if (totalAmount == 0) {
      revert InvalidParameter("totalAmount cannot be 0");
    }

    if (_stagesArray.length == 0) {
      revert InvalidParameter("stages cannot be empty");
    }

    for (uint256 i = 0; i < _stagesArray.length; i++) {
      if (_stagesArray[i].startTime >= _stagesArray[i].endTime) {
        revert InvalidParameter("Stage startTime must be less than endTime");
      }
      if (_stagesArray[i].startTime <= block.timestamp) {
        revert InvalidParameter("Stage startTime must be greater than current time");
      }

      if (earndrop.stages[_stagesArray[i].stageId].stageId != 0) {
        revert InvalidParameter("Duplicate stageId found in the same Earndrop");
      }

      earndrop.stages[_stagesArray[i].stageId] = _stagesArray[i];
    }

    bool isVerified = _verifySignature(
      _hashEarndropActivate(earndropId, tokenAddress, merkleTreeRoot, totalAmount, _stagesArray, admin), _signature
    );
    if (!isVerified) {
      revert InvalidParameter("Invalid signature");
    }

    earndrop.earndropId = uint96(earndropId);
    earndrop.tokenAddress = tokenAddress;
    earndrop.merkleTreeRoot = merkleTreeRoot;
    earndrop.totalAmount = totalAmount;
    earndrop.admin = admin;

    emit EarndropActivated(earndropId, tokenAddress, merkleTreeRoot, totalAmount, _stagesArray, admin);
  }

  function confirmActivateEarndrop(uint256 earndropId) external payable {
    Earndrop storage earndrop = earndrops[earndropId];
    if (earndrop.earndropId == 0) {
      revert InvalidParameter("Earndrop does not exist");
    }
    if (earndrop.revoked) {
      revert InvalidParameter("Earndrop revoked");
    }
    if (earndrop.confirmed) {
      revert InvalidParameter("Earndrop already confirmed");
    }
    if (msg.sender != earndrop.admin) {
      revert Unauthorized();
    }

    if (earndrop.tokenAddress == address(0)) {
      if (msg.value != earndrop.totalAmount) {
        revert InvalidParameter("Invalid amount");
      }
    } else {
      IERC20(earndrop.tokenAddress).safeTransferFrom(msg.sender, address(this), earndrop.totalAmount);
    }

    earndrop.confirmed = true;

    emit EarndropConfirmed(earndropId, msg.sender, earndrop.totalAmount);
  }

  /**
   * @dev Transfers the admin role of an Earndrop to a new address.
   * @param earndropId The unique ID of the Earndrop.
   * @param newAdmin The address of the new admin.
   */
  function transferEarndropAdmin(uint256 earndropId, address newAdmin) external {
    Earndrop storage earndrop = earndrops[earndropId];
    if (earndrop.earndropId == 0) {
      revert InvalidParameter("Earndrop does not exist");
    }
    if (msg.sender != earndrop.admin) {
      revert Unauthorized();
    }
    if (newAdmin == address(0)) {
      revert InvalidParameter("New admin cannot be the zero address");
    }

    earndrop.admin = newAdmin;

    emit EarndropAdminTransferred(earndropId, msg.sender, newAdmin);
  }

  function revokeEarndrop(uint256 earndropId) external {
    Earndrop storage earndrop = earndrops[earndropId];
    if (earndrop.earndropId == 0) {
      revert InvalidParameter("Earndrop does not exist");
    }
    if (earndrop.revoked) {
      revert InvalidParameter("Earndrop already revoked");
    }
    if (msg.sender != earndrop.admin) {
      revert Unauthorized();
    }

    earndrop.pendingRevoke = true;
    emit EarndropRevokeRequested(earndropId, msg.sender);
  }

  /**
   * @dev Cancels a pending revoke request for an Earndrop.
   * @param earndropId The unique ID of the Earndrop.
   */
  function cancelRevokeEarndrop(uint256 earndropId) external {
    Earndrop storage earndrop = earndrops[earndropId];
    if (earndrop.earndropId == 0) {
      revert InvalidParameter("Earndrop does not exist");
    }
    if (!earndrop.pendingRevoke) {
      revert InvalidParameter("No pending revoke request");
    }
    if (msg.sender != earndrop.admin) {
      revert Unauthorized();
    }

    earndrop.pendingRevoke = false;

    emit EarndropRevokeCancelled(earndropId, msg.sender);
  }

  /**
   * @dev Confirms the activation of an Earndrop by transferring funds.
   * @param earndropId The unique ID of the Earndrop.
   */
  function confirmRevokeEarndrop(uint256 earndropId) external onlyOwner {
    Earndrop storage earndrop = earndrops[earndropId];
    if (earndrop.earndropId == 0) {
      revert InvalidParameter("Earndrop does not exist");
    }
    if (earndrop.revoked) {
      revert InvalidParameter("Earndrop already revoked");
    }
    if (!earndrop.pendingRevoke) {
      revert InvalidParameter("No pending revoke request");
    }
    if (!earndrop.confirmed) {
      revert InvalidParameter("Earndrop not confirmed");
    }

    earndrop.revoked = true;
    earndrop.pendingRevoke = false;

    uint256 remainingAmount = earndrop.totalAmount - earndrop.claimedAmount;
    if (remainingAmount > 0) {
      _processTransfer(earndrop.tokenAddress, earndrop.admin, remainingAmount);
    }

    emit EarndropRevoked(earndropId, earndrop.admin, remainingAmount);
  }

  function claimEarndrop(uint256 earndropId, ClaimParams calldata params, bytes calldata _signature) external payable {
    Earndrop storage earndrop = earndrops[earndropId];
    if (earndrop.earndropId == 0) {
      revert InvalidParameter("Earndrop does not exist");
    }
    if (!earndrop.confirmed) {
      revert InvalidParameter("Earndrop not confirmed");
    }
    if (earndrop.revoked) {
      revert InvalidParameter("Earndrop revoked");
    }

    _validateStage(earndrop.stages[params.stageId]);

    if (claimed[earndropId][params.leafIndex]) {
      revert InvalidParameter("Already claimed");
    }

    // verify signature
    bool isVerified = _verifySignature(_hashEarndropClaim(earndropId, params.leafIndex, msg.value), _signature);
    if (!isVerified) {
      revert InvalidParameter("Invalid signature");
    }

    // verify merkle proof
    bytes32 leaf =
      keccak256(abi.encodePacked(earndropId, params.stageId, params.leafIndex, params.account, params.amount));
    if (!MerkleProof.verifyCalldata(params.merkleProof, earndrop.merkleTreeRoot, leaf)) {
      revert InvalidProof();
    }

    claimed[earndropId][params.leafIndex] = true;
    earndrop.claimedAmount += params.amount;

    // transfer value to treasurer
    if (msg.value > 0) {
      (bool success,) = treasurer.call{value: msg.value}("");
      if (!success) {
        revert TransferFailed();
      }
    }

    _processTransfer(earndrop.tokenAddress, params.account, params.amount);

    emit EarndropClaimed(earndropId, params.stageId, params.leafIndex, params.account, params.amount, msg.value);
  }

  function multiClaimEarndrop(uint256 earndropId, ClaimParams[] calldata params, bytes calldata signature)
    external
    payable
  {
    if (params.length == 0) {
      revert InvalidParameter("Empty params");
    }

    Earndrop storage earndrop = earndrops[earndropId];

    if (earndrop.earndropId == 0) {
      revert InvalidParameter("Earndrop does not exist");
    }
    if (!earndrop.confirmed) {
      revert InvalidParameter("Earndrop not confirmed");
    }
    if (earndrop.revoked) {
      revert InvalidParameter("Earndrop revoked");
    }

    bool isVerified = _verifySignature(_hashEarndropClaim(earndropId, params[0].leafIndex, msg.value), signature);
    if (!isVerified) {
      revert InvalidParameter("Invalid signature");
    }

    for (uint256 i = 0; i < params.length; i++) {
      ClaimParams calldata claim = params[i];

      _validateStage(earndrop.stages[claim.stageId]);

      if (claimed[earndropId][claim.leafIndex]) {
        revert InvalidParameter("Already claimed");
      }

      bytes32 leaf =
        keccak256(abi.encodePacked(earndropId, claim.stageId, claim.leafIndex, claim.account, claim.amount));
      if (!MerkleProof.verifyCalldata(claim.merkleProof, earndrop.merkleTreeRoot, leaf)) {
        revert InvalidProof();
      }

      claimed[earndropId][claim.leafIndex] = true;
      earndrop.claimedAmount += claim.amount;

      _processTransfer(earndrop.tokenAddress, claim.account, claim.amount);

      emit EarndropClaimed(earndropId, claim.stageId, claim.leafIndex, claim.account, claim.amount, msg.value);
    }

    if (msg.value > 0) {
      (bool success,) = treasurer.call{value: msg.value}("");
      if (!success) {
        revert TransferFailed();
      }
    }
  }

  function isClaimed(uint256 earndropId, uint256 leafIndex) external view returns (bool) {
    return claimed[earndropId][leafIndex];
  }

  function getEarndropStage(uint256 earndropId, uint256 stageId) external view returns (Stage memory) {
    Earndrop storage earndrop = earndrops[earndropId];
    if (earndrop.earndropId == 0) {
      revert InvalidParameter("Earndrop does not exist");
    }

    Stage memory stage = earndrop.stages[stageId];
    if (stage.stageId == 0) {
      revert InvalidParameter("Stage does not exist");
    }

    return stage;
  }

  function _validateStage(Stage memory stage) private view {
    if (stage.stageId == 0) {
      revert InvalidParameter("Stage does not exist");
    }

    if (stage.startTime > block.timestamp) {
      revert InvalidParameter("Stage not started yet");
    }
    if (stage.endTime < block.timestamp) {
      revert InvalidParameter("Stage ended");
    }
  }

  function _processTransfer(address token, address recipient, uint256 amount) private {
    if (token == address(0)) {
      (bool success,) = recipient.call{value: amount}("");
      if (!success) revert TransferFailed();
    } else {
      IERC20(token).safeTransfer(recipient, amount);
    }
  }

  // --------------- signature tools ------------- //

  function _hashEarndropActivate(
    uint256 earndropId,
    address tokenAddress,
    bytes32 merkleTreeRoot,
    uint256 totalAmount,
    Stage[] calldata _stagesArray,
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

  function _hashStages(Stage[] calldata _stagesArray) private pure returns (bytes32) {
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

  function _verifySignature(bytes32 _hash, bytes calldata _signature) private view returns (bool) {
    return ECDSA.recover(_hash, _signature) == signer;
  }
}
