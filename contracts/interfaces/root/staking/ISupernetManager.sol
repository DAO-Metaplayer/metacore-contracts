// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

/**
    @title IMetachainManager
    @author Metaplayerone Blockchain (@gretzke)
    @notice Abstract contract for managing Metachains
    @dev Should be implemented with custom desired functionality
 */
interface IMetachainManager {
    /// @notice called when a new child chain is registered
    function onInit(uint256 id) external;

    /// @notice called when a validator stakes
    function onStake(address validator, uint256 amount) external;
}
