# VestingEarndrop

VestingEarndrop is a Solidity-based smart contract designed for managing token distributions (Earndrops) with vesting schedules. This contract enables the creation of customizable token distribution plans with multi-stage unlocking periods and provides flexible management features.

## Key Features

- **Multi-stage Vesting**: Support for creating token distribution plans with multiple time-based stages
- **Merkle Tree Verification**: Efficient user eligibility verification using Merkle trees
- **EIP-712 Signature Verification**: Secure operations through signature verification
- **Multi-token Support**: Compatible with native ETH and any ERC20 tokens
- **Revocable Option**: Administrators can set whether distribution plans can be revoked
- **Batch Claims**: Users can claim tokens from multiple stages in a single transaction

## Contract Structure

### Key Data Structures

- **Stage**: Represents a time period in the distribution plan, containing start and end times
- **Earndrop**: Represents a complete distribution plan, including token address, total amount, Merkle tree root, etc.
- **ClaimParams**: Parameter set used for token claims

### Main Functions

1. **Create Distribution Plan**: Administrators can create new distribution plans, setting token type, total amount, and time stages
2. **Confirm Distribution Plan**: Plans must be confirmed and funded with the corresponding tokens after creation
3. **Claim Tokens**: Users can claim their tokens during specified time stages
4. **Batch Claims**: Users can claim tokens from multiple stages in a single transaction
5. **Revoke Distribution Plan**: Administrators can revoke revocable distribution plans and recover remaining tokens
6. **Transfer Administrative Rights**: Administrators can transfer management rights to other addresses

## Permission System

The contract implements a robust permission system with multiple roles:

### Contract Owner
- The contract owner has the highest level of authority
- Can set the signer and treasurer addresses
- Can configure whether an Earndrop is revocable
- Implements a two-step ownership transfer process for enhanced security (via Ownable2Step)

### Earndrop Admin
- Each Earndrop has a designated admin who manages that specific distribution
- Only the Earndrop admin can:
  - Confirm the activation of an Earndrop by transferring the required tokens
  - Revoke an Earndrop (if it's set as revocable)
  - Transfer admin rights for their Earndrop to another address
- This role separation allows for delegated management of individual distributions

### Signer
- Responsible for signing activation and claim operations
- All critical operations require a valid signature from this address
- Provides an additional security layer for verifying the authenticity of operations
- Can be updated by the contract owner

### Treasurer
- Receives any claim fees collected during the token claim process
- Can be updated by the contract owner

This multi-layered permission system ensures that:
1. Critical contract-wide settings can only be modified by the owner
2. Individual Earndrops can be managed independently by their respective admins
3. All sensitive operations require cryptographic verification
4. Administrative rights can be transferred securely if needed

## Security Features

- Utilizes OpenZeppelin security libraries
- EIP-712 signature verification
- Merkle tree verification
- Two-step ownership transfer
- Comprehensive error handling

## Technical Specifications

- Solidity Version: ^0.8.24
- Dependencies:
  - OpenZeppelin Contracts v5 (access control, token interfaces, safe transfers, cryptography tools)

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

## Usage Examples

### Creating and Activating a Distribution Plan

```solidity
// Create distribution stages
Stage[] memory stages = new Stage[](2);
stages[0] = Stage(block.timestamp + 1 days, block.timestamp + 7 days);
stages[1] = Stage(block.timestamp + 8 days, block.timestamp + 14 days);

// Activate distribution plan
vestingEarndrop.activateEarndrop(
    1, // earndropId
    tokenAddress, // token address
    adminAddress, // admin address
    merkleRoot, // Merkle tree root
    1000000, // total token amount
    stages, // distribution stages
    signature // signature
);

// Confirm distribution plan
vestingEarndrop.confirmActivateEarndrop(1);
```

### Setting Distribution Plan Revocability

```solidity
// Set Earndrop as revocable
vestingEarndrop.setEarndropRevocable(1, true);

// Set Earndrop as non-revocable
vestingEarndrop.setEarndropRevocable(1, false);
```

### Transferring Earndrop Admin Rights

```solidity
// Current admin transfers rights to a new admin
vestingEarndrop.transferEarndropAdmin(1, newAdminAddress);
```

### Revoking a Distribution Plan

```solidity
// Admin revokes the Earndrop and sends remaining tokens to specified address
vestingEarndrop.revokeEarndrop(1, recipientAddress);
```

### Claiming Tokens

```solidity
// Single claim
vestingEarndrop.claimEarndrop(
    1, // earndropId
    ClaimParams({
        stageIndex: 0,
        leafIndex: 123,
        account: msg.sender,
        amount: 1000,
        merkleProof: proof
    }),
    signature
);

// Batch claim
ClaimParams[] memory params = new ClaimParams[](2);
params[0] = ClaimParams({
    stageIndex: 0,
    leafIndex: 123,
    account: msg.sender,
    amount: 1000,
    merkleProof: proof1
});
params[1] = ClaimParams({
    stageIndex: 1,
    leafIndex: 456,
    account: msg.sender,
    amount: 2000,
    merkleProof: proof2
});

vestingEarndrop.multiClaimEarndrop(1, params, signature);
```

### Checking Claim Status

```solidity
// Check if a specific leaf node has been claimed
bool isClaimed = vestingEarndrop.isClaimed(1, 123);
```

### Getting Distribution Plan Stage Information

```solidity
// Get all stages for an Earndrop
Stage[] memory stages = vestingEarndrop.getEarndropStages(1);
```

### Updating Contract Key Addresses

```solidity
// Update signer address (only contract owner can execute)
vestingEarndrop.setSigner(newSignerAddress);

// Update treasurer address (only contract owner can execute)
vestingEarndrop.setTreasurer(newTreasurerAddress);
```

### Using ETH as Distribution Token

```solidity
// Create a distribution plan using ETH
vestingEarndrop.activateEarndrop(
    2, // earndropId
    address(0), // use address(0) to indicate ETH
    adminAddress,
    merkleRoot,
    1 ether, // total ETH amount
    stages,
    signature
);

// Confirm ETH distribution plan (requires sending the corresponding amount of ETH)
vestingEarndrop.confirmActivateEarndrop{value: 1 ether}(2);
```

### Token Claiming with Fees

```solidity
// User claims tokens and pays a claim fee
vestingEarndrop.claimEarndrop{value: 0.01 ether}(
    1,
    ClaimParams({
        stageIndex: 0,
        leafIndex: 123,
        account: msg.sender,
        amount: 1000,
        merkleProof: proof
    }),
    signature
);
```

## Contributions

Issue reports and pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
