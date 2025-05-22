// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

/* solhint-disable no-empty-blocks, no-inline-assembly, no-complex-fallback, payable-fallback */

import {IEntryPoint} from "@aa/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@aa/interfaces/PackedUserOperation.sol";

import {imAccount} from "@account-abstraction/account/imAccount.sol";
import {IAccountEntry} from "@account-abstraction/account/interfaces/IAccountEntry.sol";
import {IExecution} from "@account-abstraction/account/interfaces/IERC7579Account.sol";
import {IValidator} from "@account-abstraction/account/interfaces/IERC7579Module.sol";
import {ERC1271_FAIL_MAGIC} from "@account-abstraction/account/libraries/Constant.sol";
import {CallerNotCurrentValidator, CallerNotSelf, NotInitialized} from "@account-abstraction/account/libraries/Error.sol";
import {Call, executeCall, decodeBatch} from "@account-abstraction/account/libraries/Exec.sol";
import {CallType, ExecType, Mode, ModeCode, CALLTYPE_BATCH, EXECTYPE_DEFAULT} from "@account-abstraction/account/libraries/Mode.sol";
import {AccountManager} from "@account-abstraction/account/accountEntry/base/AccountManager.sol";
import {EntryManager} from "@account-abstraction/account/accountEntry/base/EntryManager.sol";
import {FallbackManager} from "@account-abstraction/account/accountEntry/base/FallbackManager.sol";
import {ValidatorManager} from "@account-abstraction/account/accountEntry/base/ValidatorManager.sol";

/// @dev Signature should be encoded as `validatorAddress || feePayerAddress || actual signature`.
uint256 constant VALIDATOR_DATA_LENGTH = 20;
uint256 constant FEE_PAYER_DATA_LENGTH = 20;

contract AccountEntryModular is
    IAccountEntry,
    AccountManager,
    EntryManager,
    ValidatorManager,
    FallbackManager
{
    using Mode for ModeCode;

    error NotCallingExecute();

    string public constant SUPPORTED_ENTRYPOINT_VERSION = "^0.7.0";

    receive() external payable {}

    /// @notice Fallback function which proxy the call to the `FallbackHandler`. If `FallbackHandler` is not set, it will revert.
    /// If the call succeed, it will return the result from the call.
    /// If the call failed, it will revert with the result from the call.
    /// @dev The proxied call is made using the `call`.
    fallback() external {
        address fh = address(getFallbackHandler());
        require(fh != address(0), NotInitialized());
        (bool success, bytes memory result) = fh.staticcall(msg.data);
        assembly {
            // If call succeed, return `result`. Otherwise revert with `result`.
            // `result` is a dynamic array with first 32 bytes being the size of the array and
            // next 32 bytes being the pointer to the start of the array.
            if iszero(success) {
                // Call failed, revert with `result`.
                // `add(result, 0x20)` gives us the pointer to the start of the array.
                // `mload(result)` loads the size of the array.
                revert(add(result, 0x20), mload(result))
            }
            // Call succeeded, return `result`.
            return(add(result, 0x20), mload(result))
        }
    }

    function initialize(
        IEntryPoint entryPoint,
        IValidator ownerValidator,
        bytes calldata ownerValidatorInitData
    ) external {
        require(msg.sender == address(this), CallerNotSelf(msg.sender));
        _setEntryPoint(entryPoint);
        _setOwnerValidator(ownerValidator, ownerValidatorInitData);
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        _validateCallData(userOp.callData);
        IValidator validator = IValidator(
            address(bytes20(userOp.signature[:VALIDATOR_DATA_LENGTH]))
        );
        require(
            isCurrentValidator(validator),
            CallerNotCurrentValidator(address(validator))
        );
        address feePayer = address(
            bytes20(
                userOp.signature[VALIDATOR_DATA_LENGTH:VALIDATOR_DATA_LENGTH +
                    FEE_PAYER_DATA_LENGTH]
            )
        );
        validationData = validator.validateUserOp(
            PackedUserOperation({
                sender: userOp.sender,
                nonce: userOp.nonce,
                initCode: userOp.initCode,
                callData: userOp.callData,
                accountGasLimits: userOp.accountGasLimits,
                preVerificationGas: userOp.preVerificationGas,
                gasFees: userOp.gasFees,
                paymasterAndData: userOp.paymasterAndData,
                // Remove validator and feePayer data inside userOp.signature according to ERC-7579
                signature: userOp.signature[VALIDATOR_DATA_LENGTH +
                    FEE_PAYER_DATA_LENGTH:]
            }),
            getCustomSignDigestForUserOp(userOpHash, feePayer) // `feePayer` is part of the signing payload
        );

        if (missingAccountFunds != 0) {
            if (feePayer != address(0)) {
                _transferFromAccount(feePayer, missingAccountFunds);
            }
            (bool success, ) = payable(msg.sender).call{
                value: missingAccountFunds
            }("");
            // ignore failure (its EntryPoint's job to verify, not account.)
            (success);
        }
    }

    /// @dev We do not check if the fee payer is our account because it may not be added to our accounts yet.
    function _transferFromAccount(address feePayer, uint256 amount) internal {
        // Instruct the fee payer account to transfer to the account entry
        Call[] memory calls = new Call[](1);
        calls[0] = Call({to: address(this), value: amount, data: ""});
        imAccount(payable(feePayer)).execute(calls);
    }

    function execute(
        ModeCode mode,
        bytes calldata executionCalldata
    ) external onlyEntryPoint {
        require(
            supportsExecutionMode(mode),
            UnsupportedERC7579ExecutionMode(mode)
        );
        // Only support callType == CALLTYPE_BATCH && execType == EXECTYPE_DEFAULT
        // CALLTYPE_BATCH: executionCalldata is encoded by batch calls
        // EXECTYPE_DEFAULT: If one of the calls fail, the transaction reverts directly
        Call[] calldata calls = decodeBatch(executionCalldata);
        for (uint256 i = 0; i < calls.length; ++i) {
            // slither-disable-next-line unused-return
            executeCall(calls[i]);
        }
    }

    function executeFromExecutor(
        ModeCode /*mode*/,
        bytes calldata /*executionCalldata*/
    ) external pure returns (bytes[] memory /*returnData*/) {
        revert UnsupportedERC7579Method();
    }

    function accountId()
        external
        pure
        returns (string memory accountImplementationId)
    {
        return "imToken.AccountEntryModular.v0.2.0";
    }

    function supportsExecutionMode(ModeCode mode) public pure returns (bool) {
        (CallType callType, ExecType execType, , ) = mode.decode();
        // Do not support `single`, `staticcall` and `delegatecall` call types
        // Do not support `try` exec type, i.e do not revert tx when fail to execute call
        return callType == CALLTYPE_BATCH && execType == EXECTYPE_DEFAULT;
    }

    function supportsModule(uint256 moduleTypeId) external pure returns (bool) {
        return _supportsModule(moduleTypeId);
    }

    function _validateCallData(bytes calldata callData) internal pure {
        bytes4 selector = bytes4(callData[:4]);
        require(selector == IExecution.execute.selector, NotCallingExecute());
    }

    function getCustomSignDigestForUserOp(
        bytes32 userOpHash,
        address feePayer
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(userOpHash, feePayer));
    }

    function getCustomSignDigestForERC1271(
        bytes32 hash,
        address account
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(hash, account));
    }

    /// @dev
    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) public view onlyAccount returns (bytes4) {
        IValidator validator = IValidator(
            address(bytes20(signature[:VALIDATOR_DATA_LENGTH]))
        );
        address account = msg.sender;
        return
            isCurrentValidator(validator)
                ? validator.isValidSignatureWithSender(
                    address(this),
                    getCustomSignDigestForERC1271(hash, account),
                    signature[VALIDATOR_DATA_LENGTH:] // Remove validator data inside signature according to ERC-7579
                )
                : ERC1271_FAIL_MAGIC;
    }
}
