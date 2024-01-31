// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "../root/staking/MetachainManager.sol";

contract MockMetachainManager is MetachainManager {
    function initialize(address stakeManager) public initializer {
        __MetachainManager_init(stakeManager);
    }

    function _onStake(address validator, uint256 amount) internal override {}
}
