// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "../../interfaces/root/staking/IStakeManager.sol";
import "../../interfaces/root/staking/IMetachainManager.sol";

abstract contract MetachainManager is IMetachainManager, Initializable {
    // slither-disable-next-line naming-convention
    IStakeManager internal _stakeManager;
    uint256 public id;

    modifier onlyStakeManager() {
        require(msg.sender == address(_stakeManager), "MetachainManager: ONLY_STAKE_MANAGER");
        _;
    }

    // slither-disable-next-line naming-convention
    function __MetachainManager_init(address newStakeManager) internal onlyInitializing {
        _stakeManager = IStakeManager(newStakeManager);
    }

    function onInit(uint256 id_) external onlyStakeManager {
        require(id == 0, "MetachainManager: ID_ALREADY_SET");
        // slither-disable-next-line events-maths
        id = id_;
    }

    function onStake(address validator, uint256 amount) external onlyStakeManager {
        _onStake(validator, amount);
    }

    function _onStake(address validator, uint256 amount) internal virtual;

    // slither-disable-next-line unused-state,naming-convention
    uint256[50] private __gap;
}
