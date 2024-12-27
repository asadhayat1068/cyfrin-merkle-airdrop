// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";


contract MerkleAirdrop is EIP712 {
    using SafeERC20 for IERC20;
// some list of addresses
// Allow someone in the list to claim tokens
    error MerkleAirdrop__InvalidProof();
    error MerkleAirdrop__AlreadyClaimed();
    error MerkleAirdrop__InvalidSignature();
    
    bytes32 private constant MESSAGE_TYPEHASH = keccak256("AirdropClaim(address account, uint256 amount)");

    bytes32 private immutable i_merkleRoot;
    IERC20 private immutable i_airdropToken;
    mapping(address claimer => bool claimed) private s_hasClaimed;

    struct AirdropClaim {
        address account;
        uint256 amount;
    }

    event Claim(address account, uint256 amount);

    constructor(bytes32 merkleRoot, IERC20 airdropToken) EIP712("MerkleAirdrop", "1") {
        i_merkleRoot = merkleRoot;
        i_airdropToken = airdropToken;
    }

    function claim(
        address _account,
        uint256 _amount,
        bytes32[] calldata _merkleProof,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // calculate the leaf
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(_account, _amount))));

        // verify the signature
        if(!_isValidSignature(_account, getMessageHash(_account, _amount), v, r, s)) {
            revert MerkleAirdrop__InvalidSignature();
        }

        // verify the proof
        if(!MerkleProof.verify(_merkleProof, i_merkleRoot, leaf)) {
            revert MerkleAirdrop__InvalidProof();
        }
        
        // check if the account has already claimed
        if(s_hasClaimed[_account]) {
            revert MerkleAirdrop__AlreadyClaimed();
        }
        // mark the account as claimed
        s_hasClaimed[_account] = true;

        // transfer the tokens
        emit Claim(_account, _amount);
        i_airdropToken.safeTransfer(_account, _amount);

    }

    function isClaimed(address _account) external view returns (bool) {
        return s_hasClaimed[_account];
    }

    function getMerkleRoot() external view returns (bytes32) {
        return i_merkleRoot;
    }

    function getAirdropToken() external view returns (IERC20) {
        return i_airdropToken;
    }

    function getMessageHash(address _account, uint256 _amount) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(MESSAGE_TYPEHASH, AirdropClaim({
                account: _account,
                amount: _amount
            })
        )));
    }

    function _isValidSignature(address _account, bytes32 _digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (bool) {
        (address actualSigner, ,) = ECDSA.tryRecover(_digest, v, r, s);
        return actualSigner == _account;
    }
}