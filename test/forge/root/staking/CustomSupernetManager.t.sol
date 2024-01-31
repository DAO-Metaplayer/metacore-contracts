// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "@utils/Test.sol";
import "contracts/common/BLS.sol";
import "contracts/root/StateSender.sol";
import {ExitHelper} from "contracts/root/ExitHelper.sol";
import {StakeManager} from "contracts/root/staking/StakeManager.sol";
import {CustomMetachainManager, Validator, GenesisValidator} from "contracts/root/staking/CustomMetachainManager.sol";
import {MockERC20} from "contracts/mocks/MockERC20.sol";
import {RootERC20Predicate} from "contracts/root/RootERC20Predicate.sol";
import "contracts/interfaces/Errors.sol";

abstract contract Uninitialized is Test {
    BLS bls;
    StateSender stateSender;
    address childValidatorSet;
    address exitHelper;
    string constant DOMAIN = "CUSTOM_Metachain_MANAGER";
    bytes32 internal constant callerSlotOnExitHelper = bytes32(uint256(3));
    MockERC20 token;
    StakeManager stakeManager;
    CustomMetachainManager MetachainManager;
    RootERC20Predicate rootERC20Predicate;

    function setUp() public virtual {
        bls = new BLS();
        stateSender = new StateSender();
        childValidatorSet = makeAddr("childValidatorSet");
        exitHelper = address(new ExitHelper());
        token = new MockERC20();
        stakeManager = StakeManager(proxify("StakeManager.sol", ""));
        MetachainManager = CustomMetachainManager(proxify("CustomMetachainManager.sol", ""));
        stakeManager.initialize(address(token));
        rootERC20Predicate = RootERC20Predicate(proxify("RootERC20Predicate.sol", ""));
    }
}

abstract contract Initialized is Uninitialized {
    function setUp() public virtual override {
        super.setUp();
        MetachainManager.initialize(
            address(stakeManager),
            address(bls),
            address(stateSender),
            address(token),
            childValidatorSet,
            exitHelper,
            address(rootERC20Predicate),
            DOMAIN
        );
    }
}

abstract contract Registered is Initialized {
    address alice = makeAddr("alice");

    function setUp() public virtual override {
        super.setUp();
        stakeManager.registerChildChain(address(MetachainManager));
    }
}

abstract contract Whitelisted is Registered {
    address bob = makeAddr("bob");

    function setUp() public virtual override {
        super.setUp();
        address[] memory validators = new address[](2);
        validators[0] = address(this);
        validators[1] = alice;
        MetachainManager.whitelistValidators(validators);
    }

    function getSignatureAndPubKey(address addr) public returns (uint256[2] memory, uint256[4] memory) {
        string[] memory cmd = new string[](5);
        cmd[0] = "npx";
        cmd[1] = "ts-node";
        cmd[2] = "test/forge/root/generateMsgMetachainManager.ts";
        cmd[3] = toHexString(addr);
        cmd[4] = toHexString(address(MetachainManager));
        bytes memory out = vm.ffi(cmd);

        (uint256[2] memory signature, uint256[4] memory pubkey) = abi.decode(out, (uint256[2], uint256[4]));

        return (signature, pubkey);
    }

    function toHexString(address addr) public pure returns (string memory) {
        bytes memory buffer = abi.encodePacked(addr);

        // Fixed buffer size for hexadecimal conversion
        bytes memory converted = new bytes(buffer.length * 2);

        bytes memory _base = "0123456789abcdef";

        for (uint256 i = 0; i < buffer.length; i++) {
            converted[i * 2] = _base[uint8(buffer[i]) / _base.length];
            converted[i * 2 + 1] = _base[uint8(buffer[i]) % _base.length];
        }

        return string(abi.encodePacked("0x", converted));
    }
}

abstract contract ValidatorsRegistered is Whitelisted {
    uint256 amount = 1000;

    function setUp() public virtual override {
        super.setUp();
        register(address(this));
        register(alice);
        token.mint(address(this), amount * 2);
        token.mint(alice, amount);
        token.mint(bob, amount);
        token.approve(address(stakeManager), type(uint256).max);
        vm.prank(alice);
        token.approve(address(stakeManager), type(uint256).max);
        vm.prank(bob);
        token.approve(address(stakeManager), type(uint256).max);
    }

    function register(address addr) public {
        (uint256[2] memory signature, uint256[4] memory pubkey) = getSignatureAndPubKey(addr);
        vm.prank(addr);
        MetachainManager.register(signature, pubkey);
    }
}

abstract contract GenesisStaked is ValidatorsRegistered {
    function setUp() public virtual override {
        super.setUp();
        stakeManager.stakeFor(1, amount);
    }
}

abstract contract FinalizedGenesis is GenesisStaked {
    function setUp() public virtual override {
        super.setUp();
        MetachainManager.finalizeGenesis();
    }
}

abstract contract EnabledStaking is FinalizedGenesis {
    function setUp() public virtual override {
        super.setUp();
        MetachainManager.enableStaking();
    }
}

abstract contract Slashed is EnabledStaking {
    bytes32 private constant SLASH_SIG = keccak256("SLASH");
    uint256 internal slashingPercentage = 50; // sent from ValidatorSet
    uint256 internal slashIncentivePercentage = 30; // sent from ValidatorSet

    function setUp() public virtual override {
        super.setUp();
        address[] memory validatorsToSlash = new address[](1);
        validatorsToSlash[0] = address(this);
        bytes memory callData = abi.encode(SLASH_SIG, validatorsToSlash, slashingPercentage, slashIncentivePercentage);
        vm.store(exitHelper, callerSlotOnExitHelper, bytes32(uint256(uint160(makeAddr("MEV"))))); // simulate caller of exit()
        vm.prank(exitHelper);
        MetachainManager.onL2StateReceive(1, childValidatorSet, callData);
        vm.store(exitHelper, callerSlotOnExitHelper, bytes32(0));
    }
}

contract CustomMetachainManager_Initialize is Uninitialized {
    function testInititialize() public {
        MetachainManager.initialize(
            address(stakeManager),
            address(bls),
            address(stateSender),
            address(token),
            childValidatorSet,
            exitHelper,
            address(rootERC20Predicate),
            DOMAIN
        );
        assertEq(MetachainManager.owner(), address(this), "should set owner");
        assertEq((MetachainManager.domain()), keccak256(abi.encodePacked(DOMAIN)), "should set and hash DOMAIN");
    }
}

contract CustomMetachainManager_RegisterWithStakeManager is Initialized {
    function test_Register() public {
        assertEq(MetachainManager.id(), 0);
        stakeManager.registerChildChain(address(MetachainManager));
        assertEq(MetachainManager.id(), 1, "should set id");
    }
}

contract CustomMetachainManager_UpdateWhitelist is Registered {
    event AddedToWhitelist(address indexed validator);

    function test_RevertNotOwner() public {
        address[] memory validators = new address[](2);
        validators[0] = address(this);
        validators[1] = alice;
        vm.expectRevert("Ownable: caller is not the owner");
        vm.prank(alice);
        MetachainManager.whitelistValidators(validators);
    }

    function testUpdateWhitelist() public {
        address[] memory validators = new address[](2);
        validators[0] = address(this);
        validators[1] = alice;
        vm.expectEmit(true, true, true, true);
        emit AddedToWhitelist(address(this));
        vm.expectEmit(true, true, true, true);
        emit AddedToWhitelist(alice);
        MetachainManager.whitelistValidators(validators);
        assertTrue(MetachainManager.getValidator(address(this)).isWhitelisted, "should whitelist validator");
        assertTrue(MetachainManager.getValidator(alice).isWhitelisted, "should whitelist validator");
    }
}

contract CustomMetachainManager_RegisterValidator is Whitelisted {
    event ValidatorRegistered(address indexed validator, uint256[4] blsKey);
    event RemovedFromWhitelist(address indexed validator);

    function test_RevertValidatorNotWhitelisted() public {
        vm.expectRevert(abi.encodeWithSelector(Unauthorized.selector, "WHITELIST"));
        vm.prank(bob);
        uint256[2] memory signature;
        uint256[4] memory pubkey;
        MetachainManager.register(signature, pubkey);
    }

    function test_RevertEmptySignature() public {
        uint256[2] memory signature = [uint256(0), uint256(0)];
        uint256[4] memory pubkey = [uint256(0), uint256(0), uint256(0), uint256(0)];
        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, address(this)));
        MetachainManager.register(signature, pubkey);
    }

    function test_RevertInvalidSignature() public {
        (uint256[2] memory signature, uint256[4] memory pubkey) = getSignatureAndPubKey(address(this));
        signature[0] = signature[0] + 1;
        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, address(this)));
        MetachainManager.register(signature, pubkey);
    }

    function test_SuccessfulRegistration() public {
        (uint256[2] memory signature, uint256[4] memory pubkey) = getSignatureAndPubKey(address(this));
        vm.expectEmit(true, true, true, true);
        emit RemovedFromWhitelist(address(this));
        vm.expectEmit(true, true, true, true);
        emit ValidatorRegistered(address(this), pubkey);
        MetachainManager.register(signature, pubkey);
        Validator memory validator = MetachainManager.getValidator(address(this));
        assertEq(
            keccak256(abi.encodePacked(validator.blsKey)),
            keccak256(abi.encodePacked(pubkey)),
            "should set blsKey"
        );
        assertTrue(validator.isActive, "should set isRegistered");
        assertFalse(validator.isWhitelisted, "should remove from whitelist");
    }
}

contract CustomMetachainManager_StakeGenesis is ValidatorsRegistered {
    function test_RevertNotRegistered() public {
        vm.expectRevert(abi.encodeWithSelector(Unauthorized.selector, "VALIDATOR"));
        vm.prank(bob);
        stakeManager.stakeFor(1, amount);
    }

    function test_SuccessfulStakeGenesis() public {
        stakeManager.stakeFor(1, amount);
        GenesisValidator[] memory genesisValidators = MetachainManager.genesisSet();
        assertEq(genesisValidators.length, 1, "should set genesisSet");
        GenesisValidator memory validator = genesisValidators[0];
        assertEq(validator.addr, address(this), "should set validator address");
        assertEq(validator.initialStake, amount, "should set amount");
    }

    function test_MultipleStakes() public {
        stakeManager.stakeFor(1, amount / 2);
        stakeManager.stakeFor(1, amount / 2);
        GenesisValidator[] memory genesisValidators = MetachainManager.genesisSet();
        assertEq(genesisValidators.length, 1, "should set genesisSet");
        GenesisValidator memory validator = genesisValidators[0];
        assertEq(validator.addr, address(this), "should set validator address");
        assertEq(validator.initialStake, amount, "should set amount");
    }
}

contract CustomMetachainManager_FinalizeGenesis is GenesisStaked {
    event GenesisFinalized(uint256 amountValidators);

    function test_RevertNotOwner() public {
        vm.expectRevert("Ownable: caller is not the owner");
        vm.prank(alice);
        MetachainManager.finalizeGenesis();
    }

    function test_RevertEnableStaking() public {
        vm.expectRevert("GenesisLib: not finalized");
        MetachainManager.enableStaking();
    }

    function test_SuccessFinaliseGenesis() public {
        vm.expectEmit(true, true, true, true);
        emit GenesisFinalized(1);
        MetachainManager.finalizeGenesis();
    }
}

contract CustomMetachainManager_EnableStaking is FinalizedGenesis {
    event StakingEnabled();

    function test_RevertNotOwner() public {
        vm.expectRevert("Ownable: caller is not the owner");
        vm.prank(alice);
        MetachainManager.enableStaking();
    }

    function test_RevertFinalizeGenesis() public {
        vm.expectRevert("GenesisLib: already finalized");
        MetachainManager.finalizeGenesis();
    }

    function test_RevertStaking() public {
        vm.expectRevert(abi.encodeWithSelector(Unauthorized.selector, "Wait for genesis"));
        stakeManager.stakeFor(1, amount);
    }

    function test_SuccessEnableStaking() public {
        vm.expectEmit(true, true, true, true);
        emit StakingEnabled();
        MetachainManager.enableStaking();
    }
}

contract CustomMetachainManager_PostGenesis is EnabledStaking {
    function test_RevertEnableStaking() public {
        vm.expectRevert("GenesisLib: already enabled");
        MetachainManager.enableStaking();
    }
}

contract CustomMetachainManager_StakingPostGenesis is EnabledStaking {
    event StateSynced(uint256 indexed id, address indexed sender, address indexed receiver, bytes data);

    bytes32 private constant STAKE_SIG = keccak256("STAKE");

    function test_SuccessfulStakePostGenesis() public {
        vm.expectEmit(true, true, true, true);
        emit StateSynced(1, address(MetachainManager), childValidatorSet, abi.encode(STAKE_SIG, address(this), amount));
        stakeManager.stakeFor(1, amount);
    }
}

contract CustomMetachainManager_Unstake is EnabledStaking {
    bytes32 private constant UNSTAKE_SIG = keccak256("UNSTAKE");
    event ValidatorDeactivated(address indexed validator);

    function test_RevertNotCalledByExitHelper() public {
        vm.expectRevert(abi.encodeWithSelector(Unauthorized.selector, "_exitHelper"));
        MetachainManager.onL2StateReceive(1, childValidatorSet, "");
    }

    function test_RevertChildValidatorSetNotSender() public {
        vm.expectRevert(abi.encodeWithSelector(Unauthorized.selector, "_exitHelper"));
        vm.prank(exitHelper);
        MetachainManager.onL2StateReceive(1, alice, "");
    }

    function test_SuccessfulFullWithdrawal() public {
        bytes memory callData = abi.encode(UNSTAKE_SIG, address(this), amount);
        vm.expectEmit(true, true, true, true);
        emit ValidatorDeactivated(address(this));
        vm.prank(exitHelper);
        MetachainManager.onL2StateReceive(1, childValidatorSet, callData);
        assertEq(stakeManager.stakeOf(address(this), 1), 0, "should withdraw all");
        assertEq(MetachainManager.getValidator(address(this)).isActive, false, "should deactivate");
    }

    function test_SuccessfulPartWithdrawal(uint256 unstakeAmount) public {
        vm.assume(unstakeAmount != 0 && unstakeAmount < amount);
        bytes memory callData = abi.encode(UNSTAKE_SIG, address(this), unstakeAmount);
        vm.prank(exitHelper);
        MetachainManager.onL2StateReceive(1, childValidatorSet, callData);
        assertEq(stakeManager.stakeOf(address(this), 1), amount - unstakeAmount, "should not withdraw all");
        assertEq(MetachainManager.getValidator(address(this)).isActive, true, "should not deactivate");
    }
}

contract CustomMetachainManager_PremineInitialized is Initialized {
    uint256 balance = 100 ether;
    event GenesisBalanceAdded(address indexed account, uint256 indexed amount);

    address childERC20Predicate;
    address childTokenTemplate;
    address bob = makeAddr("bob");

    function setUp() public virtual override {
        super.setUp();
        token.mint(bob, balance);
        childERC20Predicate = makeAddr("childERC20Predicate");
        childTokenTemplate = makeAddr("childTokenTemplate");
        rootERC20Predicate.initialize(
            address(stateSender),
            exitHelper,
            childERC20Predicate,
            childTokenTemplate,
            address(token)
        );
    }

    function test_addGenesisBalance_successful() public {
        vm.startPrank(bob);
        token.approve(address(MetachainManager), balance);
        vm.expectEmit(true, true, true, true);
        emit GenesisBalanceAdded(bob, balance);
        MetachainManager.addGenesisBalance(balance);

        GenesisValidator[] memory genesisAccounts = MetachainManager.genesisSet();
        assertEq(genesisAccounts.length, 1, "should set genesisSet");
        GenesisValidator memory account = genesisAccounts[0];
        assertEq(account.addr, bob, "should set validator address");
        assertEq(account.initialStake, 0, "should set initial stake to 0");

        uint256 actualBalance = MetachainManager.genesisBalances(account.addr);
        assertEq(actualBalance, balance, "should set genesis balance");
    }

    function test_addGenesisBalance_genesisSetFinalizedRevert() public {
        MetachainManager.finalizeGenesis();
        MetachainManager.enableStaking();
        vm.expectRevert("CustomMetachainManager: GENESIS_SET_IS_ALREADY_FINALIZED");
        MetachainManager.addGenesisBalance(balance);
    }

    function test_addGenesisBalance_invalidAmountRevert() public {
        vm.expectRevert("CustomMetachainManager: INVALID_AMOUNT");
        MetachainManager.addGenesisBalance(0);
    }
}

contract CustomMetachainManager_UndefinedRootERC20Predicate is Uninitialized {
    function setUp() public virtual override {
        super.setUp();
        MetachainManager.initialize(
            address(stakeManager),
            address(bls),
            address(stateSender),
            address(token),
            childValidatorSet,
            exitHelper,
            address(0),
            DOMAIN
        );
    }

    function test_addGenesisBalance_revertUndefinedRootERC20Predicate() public {
        vm.expectRevert(
            abi.encodeWithSelector(Unauthorized.selector, "CustomMetachainManager: UNDEFINED_ROOT_ERC20_PREDICATE")
        );
        MetachainManager.addGenesisBalance(100 ether);
    }
}

contract CustomMetachainManager_UndefinedNativeTokenRoot is Initialized {
    function test_addGenesisBalance_revertUndefinedNativeTokenRoot() public {
        vm.expectRevert(
            abi.encodeWithSelector(Unauthorized.selector, "CustomMetachainManager: UNDEFINED_NATIVE_TOKEN_ROOT")
        );
        MetachainManager.addGenesisBalance(100 ether);
    }
}
