// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

/* solhint-disable immutable-vars-naming, no-complex-fallback, payable-fallback */

import {ECDSA} from "@oz/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@oz/utils/cryptography/MessageHashUtils.sol";

import {ERC1271_SUCCESS_MAGIC, ERC1271_FAIL_MAGIC} from "@account-abstraction/account/libraries/Constant.sol";
import {Call, executeCall} from "@account-abstraction/account/libraries/Exec.sol";

contract imAccount7702 {
    receive() external payable {}

    error CallerNotSelf();

    function execute(Call[] calldata calls) external {
        require(msg.sender == address(this), CallerNotSelf());
        for (uint256 i = 0; i < calls.length; ++i) {
            // slither-disable-next-line unused-return
            executeCall(calls[i]);
        }
    }

    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) public view returns (bytes4) {
        return
            (ECDSA.recover(
                MessageHashUtils.toEthSignedMessageHash(hash),
                signature
            ) == address(this))
                ? ERC1271_SUCCESS_MAGIC
                : ERC1271_FAIL_MAGIC;
    }

    function accountId()
        external
        pure
        returns (string memory accountImplementationId)
    {
        return "imToken.Account.v0.2.0";
    }
}
