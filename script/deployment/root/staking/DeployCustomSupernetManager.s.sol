// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "forge-std/Script.sol";

import {CustomMetachainManager} from "contracts/root/staking/CustomMetachainManager.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

abstract contract CustomMetachainManagerDeployer is Script {
    function deployCustomMetachainManager(
        address proxyAdmin,
        address newStakeManager,
        address newBls,
        address newStateSender,
        address newMatic,
        address newChildValidatorSet,
        address newExitHelper,
        address newRootERC20Predicate,
        string memory newDomain
    ) internal returns (address logicAddr, address proxyAddr) {
        bytes memory initData = abi.encodeCall(
            CustomMetachainManager.initialize,
            (
                newStakeManager,
                newBls,
                newStateSender,
                newMatic,
                newChildValidatorSet,
                newExitHelper,
                newRootERC20Predicate,
                newDomain
            )
        );

        vm.startBroadcast();

        CustomMetachainManager customMetachainManager = new CustomMetachainManager();

        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(customMetachainManager),
            proxyAdmin,
            initData
        );

        vm.stopBroadcast();

        logicAddr = address(customMetachainManager);
        proxyAddr = address(proxy);
    }
}

contract DeployCustomMetachainManager is CustomMetachainManagerDeployer {
    function run(
        address proxyAdmin,
        address newStakeManager,
        address newBls,
        address newStateSender,
        address newMatic,
        address newChildValidatorSet,
        address newExitHelper,
        address newRootERC20Predicate,
        string memory newDomain
    ) external returns (address logicAddr, address proxyAddr) {
        return
            deployCustomMetachainManager(
                proxyAdmin,
                newStakeManager,
                newBls,
                newStateSender,
                newMatic,
                newChildValidatorSet,
                newExitHelper,
                newRootERC20Predicate,
                newDomain
            );
    }
}
