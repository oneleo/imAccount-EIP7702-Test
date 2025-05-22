// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

/* solhint-disable immutable-vars-naming, no-complex-fallback, payable-fallback */

import {ECDSA} from "@oz/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@oz/utils/cryptography/MessageHashUtils.sol";

import {AlreadyInitialized, CallerNotAccountEntry, CallerNotDeployer, CallerNotAccountEntryOrExecutor, InvalidParamZeroAddress, NotInitialized} from "@account-abstraction/account/libraries/Error.sol";
import {Call, executeCall} from "@account-abstraction/account/libraries/Exec.sol";

contract imAccount {
    address public immutable deployer;
    address public accountEntry;
    address public executor;

    event AccountEntryChanged(address indexed accountEntry);
    event ExecutorChanged(address indexed executor);

    error InvalidSelfSignatureFor7702();

    modifier onlyAccountEntry() {
        require(msg.sender == accountEntry, CallerNotAccountEntry(msg.sender));
        _;
    }

    modifier onlyAccountEntryOrExecutor() {
        require(
            msg.sender == accountEntry || msg.sender == executor,
            CallerNotAccountEntryOrExecutor(msg.sender)
        );
        _;
    }

    constructor() {
        deployer = msg.sender;
    }

    receive() external payable {}

    /// @notice Fallback function which proxy the call to the `accountEntry`.
    /// If the call succeed, it will return the result from the call.
    /// If the call failed, it will revert with the result from the call.
    fallback() external {
        require(accountEntry != address(0), NotInitialized());
        (bool success, bytes memory result) = _doFallback2771Call(accountEntry);
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

    // Initialization for non-7702 flow
    function initialize(address accountEntry_) external {
        require(msg.sender == deployer, CallerNotDeployer(msg.sender));
        require(accountEntry == address(0), AlreadyInitialized());
        _setAccountEntry(accountEntry_);
    }

    // Initialization for 7702 flow
    function initializeFor7702(
        address accountEntry_,
        bytes calldata selfSignatureFor7702
    ) external {
        if (msg.sender != address(this)) {
            // FIXME: Need replay protection for 7702 signature
            require(
                ECDSA.recover(
                    MessageHashUtils.toEthSignedMessageHash(
                        abi.encode(accountEntry_)
                    ),
                    selfSignatureFor7702
                ) == address(this),
                InvalidSelfSignatureFor7702()
            );
        }
        require(accountEntry == address(0), AlreadyInitialized());
        _setAccountEntry(accountEntry_);
    }

    function setAccountEntry(address accountEntry_) external onlyAccountEntry {
        _setAccountEntry(accountEntry_);
    }

    function _setAccountEntry(address accountEntry_) internal {
        require(accountEntry_ != address(0), InvalidParamZeroAddress());
        accountEntry = accountEntry_;

        emit AccountEntryChanged(accountEntry_);
    }

    function setExecutor(address executor_) external onlyAccountEntry {
        executor = executor_;

        emit ExecutorChanged(executor_);
    }

    function execute(
        Call[] calldata calls
    ) external onlyAccountEntryOrExecutor {
        for (uint256 i = 0; i < calls.length; ++i) {
            // slither-disable-next-line unused-return
            executeCall(calls[i]);
        }
    }

    function accountId()
        external
        pure
        returns (string memory accountImplementationId)
    {
        return "imToken.Account.v0.2.0";
    }

    // Copy from https://github.com/zerodevapp/kernel/blob/d191610915395232ecebe80d67f82482edd87f4e/src/utils/ExecLib.sol#L245C5-L269C6
    function _doFallback2771Call(
        address target
    ) internal returns (bool success, bytes memory result) {
        assembly {
            function allocate(length) -> pos {
                pos := mload(0x40)
                mstore(0x40, add(pos, length))
            }

            let calldataPtr := allocate(calldatasize())
            calldatacopy(calldataPtr, 0, calldatasize())

            // The msg.sender address is shifted to the left by 12 bytes to remove the padding
            // Then the address without padding is stored right after the calldata
            let senderPtr := allocate(20)
            mstore(senderPtr, shl(96, caller()))

            // Add 20 bytes for the address appended add the end
            success := call(
                gas(),
                target,
                0,
                calldataPtr,
                add(calldatasize(), 20),
                0,
                0
            )

            result := mload(0x40)
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }
}
