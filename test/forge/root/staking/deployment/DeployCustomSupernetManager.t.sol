// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "forge-std/Test.sol";

import {DeployCustomMetachainManager} from "script/deployment/root/staking/DeployCustomMetachainManager.s.sol";

import {CustomMetachainManager} from "contracts/root/staking/CustomMetachainManager.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract DeployCustomMetachainManagerTest is Test {
    DeployCustomMetachainManager private deployer;

    address logicAddr;
    address proxyAddr;

    CustomMetachainManager internal proxyAsCustomMetachainManager;
    ITransparentUpgradeableProxy internal proxy;

    address proxyAdmin;
    address newStakeManager;
    address newBls;
    address newStateSender;
    address newMatic;
    address newChildValidatorSet;
    address newExitHelper;
    address newRootERC20Predicate;
    string newDomain;

    function setUp() public {
        deployer = new DeployCustomMetachainManager();

        proxyAdmin = makeAddr("proxyAdmin");
        newStakeManager = makeAddr("newStakeManager");
        newBls = makeAddr("newBls");
        newStateSender = makeAddr("newStateSender");
        newMatic = makeAddr("newMatic");
        newChildValidatorSet = makeAddr("newChildValidatorSet");
        newExitHelper = makeAddr("newExitHelper");
        newRootERC20Predicate = makeAddr("newRootERC20Predicate");
        newDomain = "newDomain";

        (logicAddr, proxyAddr) = deployer.run(
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
        _recordProxy(proxyAddr);
    }

    function testRun() public {
        vm.startPrank(proxyAdmin);

        assertEq(proxy.admin(), proxyAdmin);
        assertEq(proxy.implementation(), logicAddr);

        vm.stopPrank();
    }

    function testInitialization() public {
        vm.expectRevert("Initializable: contract is already initialized");
        proxyAsCustomMetachainManager.initialize(
            newStakeManager,
            newBls,
            newStateSender,
            newMatic,
            newChildValidatorSet,
            newExitHelper,
            newRootERC20Predicate,
            newDomain
        );

        assertEq(
            vm.load(address(proxyAsCustomMetachainManager), bytes32(uint(151))),
            bytes32(bytes.concat(hex"000000000000000000000000", abi.encodePacked(newStakeManager)))
        );
        assertEq(
            vm.load(address(proxyAsCustomMetachainManager), bytes32(uint(203))),
            bytes32(bytes.concat(hex"000000000000000000000000", abi.encodePacked(newBls)))
        );
        assertEq(
            vm.load(address(proxyAsCustomMetachainManager), bytes32(uint(204))),
            bytes32(bytes.concat(hex"000000000000000000000000", abi.encodePacked(newStateSender)))
        );
        assertEq(
            vm.load(address(proxyAsCustomMetachainManager), bytes32(uint(205))),
            bytes32(bytes.concat(hex"000000000000000000000000", abi.encodePacked(newMatic)))
        );
        assertEq(
            vm.load(address(proxyAsCustomMetachainManager), bytes32(uint(206))),
            bytes32(bytes.concat(hex"000000000000000000000000", abi.encodePacked(newChildValidatorSet)))
        );
        assertEq(
            vm.load(address(proxyAsCustomMetachainManager), bytes32(uint(207))),
            bytes32(bytes.concat(hex"000000000000000000000000", abi.encodePacked(newExitHelper)))
        );
        assertEq(proxyAsCustomMetachainManager.domain(), keccak256(abi.encodePacked(newDomain)));
    }

    function testLogicChange() public {
        address newLogicAddr = makeAddr("newLogicAddr");
        vm.etch(newLogicAddr, hex"00");

        vm.startPrank(proxyAdmin);

        proxy.upgradeTo(newLogicAddr);
        assertEq(proxy.implementation(), newLogicAddr);

        vm.stopPrank();
    }

    function testAdminChange() public {
        address newAdmin = makeAddr("newAdmin");

        vm.prank(proxyAdmin);
        proxy.changeAdmin(newAdmin);

        vm.prank(newAdmin);
        assertEq(proxy.admin(), newAdmin);
    }

    function _recordProxy(address _proxyAddr) internal {
        proxyAsCustomMetachainManager = CustomMetachainManager(_proxyAddr);
        proxy = ITransparentUpgradeableProxy(payable(address(_proxyAddr)));
    }
}
