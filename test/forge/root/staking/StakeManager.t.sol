// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "@utils/Test.sol";
import {StakeManager} from "contracts/root/staking/StakeManager.sol";
import {MockMetachainManager} from "contracts/mocks/MockMetachainManager.sol";
import {MockERC20} from "contracts/mocks/MockERC20.sol";

abstract contract Uninitialized is Test {
    MockERC20 token;
    StakeManager stakeManager;
    MockMetachainManager MetachainManager;

    function setUp() public virtual {
        token = new MockERC20();
        stakeManager = StakeManager(proxify("StakeManager.sol", ""));
        MetachainManager = new MockMetachainManager();
    }
}

abstract contract Initialized is Uninitialized {
    function setUp() public virtual override {
        super.setUp();
        stakeManager.initialize(address(token));
        MetachainManager.initialize(address(stakeManager));
    }
}

abstract contract Registered is Initialized {
    uint256 maxAmount = 1000000 ether;
    MockMetachainManager MetachainManager2;
    uint256 id;
    uint256 id2;
    address alice;

    function setUp() public virtual override {
        super.setUp();
        alice = makeAddr("alice");
        MetachainManager2 = new MockMetachainManager();
        MetachainManager2.initialize(address(stakeManager));
        id = stakeManager.registerChildChain(address(MetachainManager));
        id2 = stakeManager.registerChildChain(address(MetachainManager2));
        token.mint(address(this), maxAmount * 2);
        token.mint(alice, maxAmount);
        token.approve(address(stakeManager), type(uint256).max);
        vm.prank(alice);
        token.approve(address(stakeManager), type(uint256).max);
    }
}

abstract contract Staked is Registered {
    function setUp() public virtual override {
        super.setUp();
        stakeManager.stakeFor(id, maxAmount);
    }
}

abstract contract Unstaked is Staked {
    address bob = makeAddr("bob");

    function setUp() public virtual override {
        super.setUp();
        vm.prank(address(MetachainManager));
        stakeManager.releaseStakeOf(address(this), maxAmount);
    }
}

contract StakeManager_Initialize is Uninitialized {
    function testInititialize() public {
        stakeManager.initialize(address(token));
        MetachainManager.initialize(address(stakeManager));
    }
}

contract StakeManager_Register is Initialized, StakeManager {
    function test_RevertFailingCallback() public {
        vm.expectRevert(bytes(""));
        stakeManager.registerChildChain(address(token));
    }

    function test_RegisterChildChain() public {
        vm.expectEmit(true, true, true, true);
        emit ChildManagerRegistered(1, address(MetachainManager));
        uint256 id = stakeManager.registerChildChain(address(MetachainManager));
        assertEq(stakeManager.idFor(address(MetachainManager)), id, "id mismatch on stake manager");
        assertEq(address(stakeManager.managerOf(id)), address(MetachainManager), "manager mismatch on stake manager");
        assertEq(MetachainManager.id(), id, "id mismatch on Metachain manager");
        assertGt(id, 0, "id is zero");
    }
}

contract StakeManager_StakeFor is Registered, StakeManager {
    function test_RevertIdZero() public {
        vm.expectRevert("StakeManager: INVALID_ID");
        stakeManager.stakeFor(0, 1);
    }

    function test_RevertChainDoesNotExist() public {
        vm.expectRevert("StakeManager: INVALID_ID");
        stakeManager.stakeFor(id2 + 1, 1);
    }

    function test_StakeFor(uint256 amount) public {
        vm.assume(amount <= maxAmount);
        vm.expectEmit(true, true, true, true);
        emit StakeAdded(id, address(this), amount);
        stakeManager.stakeFor(id, amount);
        assertEq(stakeManager.totalStake(), amount, "total stake mismatch");
        assertEq(stakeManager.totalStakeOfChild(id), amount, "total stake of child mismatch");
        assertEq(stakeManager.totalStakeOf(address(this)), amount, "total stake of mismatch");
        assertEq(stakeManager.stakeOf(address(this), 1), amount, "stake of mismatch");
        assertEq(token.balanceOf(address(stakeManager)), amount, "token balance mismatch");
    }

    function test_StakeForMultiple(uint256 amount1, uint256 amount2, uint256 amount3) public {
        vm.assume(amount1 <= maxAmount && amount2 <= maxAmount && amount3 <= maxAmount);
        stakeManager.stakeFor(id, amount1);
        stakeManager.stakeFor(id2, amount2);
        vm.prank(alice);
        stakeManager.stakeFor(id, amount3);
        assertEq(stakeManager.totalStake(), amount1 + amount2 + amount3, "total stake mismatch");
        assertEq(stakeManager.totalStakeOfChild(id), amount1 + amount3, "total stake of child mismatch");
        assertEq(stakeManager.totalStakeOfChild(id2), amount2, "total stake of child mismatch");
        assertEq(stakeManager.totalStakeOf(address(this)), amount1 + amount2, "total stake of mismatch");
        assertEq(stakeManager.totalStakeOf(alice), amount3, "total stake of mismatch");
        assertEq(stakeManager.stakeOf(address(this), id), amount1, "stake of mismatch");
        assertEq(stakeManager.stakeOf(address(this), id2), amount2, "stake of mismatch");
        assertEq(stakeManager.stakeOf(alice, id), amount3, "stake of mismatch");
        assertEq(token.balanceOf(address(stakeManager)), amount1 + amount2 + amount3, "token balance mismatch");
    }
}

contract StakeManager_ReleaseStake is Staked, StakeManager {
    function test_RevertNotMetachainManager() public {
        vm.expectRevert("StakeManagerChildData: INVALID_MANAGER");
        stakeManager.releaseStakeOf(address(this), 1);
    }

    function test_ReleaseStakeFor(uint256 amount) public {
        vm.assume(amount <= maxAmount);
        vm.expectEmit(true, true, true, true);
        emit StakeRemoved(id, address(this), amount);
        vm.prank(address(MetachainManager));
        stakeManager.releaseStakeOf(address(this), amount);
        assertEq(stakeManager.totalStake(), maxAmount - amount, "total stake mismatch");
        assertEq(stakeManager.totalStakeOfChild(id), maxAmount - amount, "total stake of child mismatch");
        assertEq(stakeManager.totalStakeOf(address(this)), maxAmount - amount, "total stake of mismatch");
        assertEq(stakeManager.stakeOf(address(this), 1), maxAmount - amount, "stake of mismatch");
        assertEq(stakeManager.withdrawableStake(address(this)), amount, "withdrawable stake mismatch");
    }
}

contract StakeManager_WithdrawStake is Unstaked, StakeManager {
    function test_WithdrawStake(uint256 amount) public {
        vm.assume(amount <= maxAmount);
        vm.expectEmit(true, true, true, true);
        emit StakeWithdrawn(address(this), bob, amount);
        stakeManager.withdrawStake(bob, amount);
        assertEq(stakeManager.withdrawableStake(address(this)), maxAmount - amount, "withdrawable stake mismatch");
    }
}
