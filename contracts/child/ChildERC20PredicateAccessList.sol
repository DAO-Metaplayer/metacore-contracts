// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {ChildERC20Predicate} from "./ChildERC20Predicate.sol";
import {AccessList} from "../lib/AccessList.sol";

/**
    @title ChildERC20PredicateAccessList
    @author Metaplayerone Blockchain
    @notice Enables ERC20 token deposits and withdrawals (only from allowlisted address, and not from blocklisted addresses) across an arbitrary root chain and child chain
 */
// solhint-disable reason-string
contract ChildERC20PredicateAccessList is AccessList, ChildERC20Predicate {
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address newL2StateSender,
        address newStateReceiver,
        address newRootERC20Predicate,
        address newChildTokenTemplate,
        address newNativeTokenRootAddress,
        bool newUseAllowList,
        bool newUseBlockList,
        address newOwner
    ) public virtual onlySystemCall initializer {
        _initialize(
            newL2StateSender,
            newStateReceiver,
            newRootERC20Predicate,
            newChildTokenTemplate,
            newNativeTokenRootAddress
        );
        _initializeAccessList(newUseAllowList, newUseBlockList);
        _transferOwnership(newOwner);
    }

    function _beforeTokenWithdraw() internal virtual override {
        _checkAccessList();
    }

    // slither-disable-next-line unused-state,naming-convention
    uint256[50] private __gap;
}
