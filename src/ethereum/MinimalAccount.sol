// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract MinimalAccount is IAccount, Ownable {
    /*//////////////////////////////////////////////////////////////
                            EXTERNAL ERRORS
    //////////////////////////////////////////////////////////////*/
    error MinimalAccount__NotFromEntryPoint();
    error MinimalAccount__NotFromEntryPointOrOwner();
    error MinimalAccount__CallFailed(bytes);
    error MinimalAccount__PreFundFailed();

    /*//////////////////////////////////////////////////////////////
                        EXTERNAL STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    IEntryPoint private immutable I_ENTRYPOINT;

    /*//////////////////////////////////////////////////////////////
                           EXTERNAL MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier requireFromEntryPoint() {
        if (msg.sender != address(I_ENTRYPOINT)) {
            revert MinimalAccount__NotFromEntryPoint();
        }
        _;
    }
    modifier requireEntryPointOrOwner() {
        if (msg.sender != address(I_ENTRYPOINT) && msg.sender != owner()) {
            revert MinimalAccount__NotFromEntryPointOrOwner();
        }
        _;
    }
    // entrypoint -> this contract
    /*
    struct PackedUserOperation {
        address sender; ///// our minimal account
        uint256 nonce;  ///// number only used once, nonce
        bytes initCode; //// ignore for now
        bytes callData; //// this is where we put "the good stuff".
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
        bytes signature;
    }
    */

    constructor(address entryPoint) Ownable(msg.sender) {
        I_ENTRYPOINT = IEntryPoint(entryPoint);
    }

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    // A signature is valid, if it's the Minimal account owner
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        requireFromEntryPoint
        returns (uint256)
    {
        // we need to validate signature `bytes signature` against all other parameter in the struct
        uint256 validationData = _validateSignature(userOp, userOpHash);
        // _validateNonce()

        _payPrefund(missingAccountFunds);

        return validationData;
    }

    // userOpHash
    // EIP-191 version of the signed hash
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);
        if (signer != owner()) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            if (!success) {
                revert MinimalAccount__PreFundFailed();
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                           EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    receive() external payable {}

    function execute(address dest, uint256 value, bytes calldata functionData) external requireEntryPointOrOwner {
        (bool success, bytes memory result) = dest.call{value: value}(functionData);
        if (!success) {
            revert MinimalAccount__CallFailed(result);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                GETTERS
    //////////////////////////////////////////////////////////////*/

    function getEntryPoint() external view returns (address) {
        return address(I_ENTRYPOINT);
    }
}
