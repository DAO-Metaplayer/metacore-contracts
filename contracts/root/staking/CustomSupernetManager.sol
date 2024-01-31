// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./MetachainManager.sol";
import "../../interfaces/common/IBLS.sol";
import "../../interfaces/IStateSender.sol";
import "../../interfaces/root/staking/ICustomMetachainManager.sol";
import "../../interfaces/root/IRootERC20Predicate.sol";

contract CustomMetachainManager is ICustomMetachainManager, Ownable2StepUpgradeable, MetachainManager {
    using SafeERC20 for IERC20;
    using GenesisLib for GenesisSet;

    bytes32 private constant _STAKE_SIG = keccak256("STAKE");
    bytes32 private constant _UNSTAKE_SIG = keccak256("UNSTAKE");

    IBLS private _bls;
    IStateSender private _stateSender;
    IERC20 private _matic;
    address private _childValidatorSet;
    address private _exitHelper;

    bytes32 public domain;

    GenesisSet private _genesis;
    mapping(address => Validator) public validators;
    IRootERC20Predicate private _rootERC20Predicate;
    mapping(address => uint256) public genesisBalances;

    modifier onlyValidator(address validator) {
        if (!validators[validator].isActive) revert Unauthorized("VALIDATOR");
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address newStakeManager,
        address newBls,
        address newStateSender,
        address newMatic,
        address newChildValidatorSet,
        address newExitHelper,
        address newRootERC20Predicate,
        string memory newDomain
    ) public initializer {
        require(
            newStakeManager != address(0) &&
                newBls != address(0) &&
                newStateSender != address(0) &&
                newMatic != address(0) &&
                newChildValidatorSet != address(0) &&
                newExitHelper != address(0) &&
                bytes(newDomain).length != 0,
            "INVALID_INPUT"
        );

        __MetachainManager_init(newStakeManager);
        _bls = IBLS(newBls);
        _stateSender = IStateSender(newStateSender);
        _matic = IERC20(newMatic);
        _childValidatorSet = newChildValidatorSet;
        _exitHelper = newExitHelper;
        _rootERC20Predicate = IRootERC20Predicate(newRootERC20Predicate);
        domain = keccak256(abi.encodePacked(newDomain));
        __Ownable2Step_init();
    }

    /**
     * @inheritdoc ICustomMetachainManager
     */
    function whitelistValidators(address[] calldata validators_) external onlyOwner {
        uint256 length = validators_.length;
        for (uint256 i = 0; i < length; i++) {
            _addToWhitelist(validators_[i]);
        }
    }

    /**
     * @inheritdoc ICustomMetachainManager
     */
    function register(uint256[2] calldata signature, uint256[4] calldata pubkey) external {
        Validator storage validator = validators[msg.sender];
        if (!validator.isWhitelisted) revert Unauthorized("WHITELIST");
        _verifyValidatorRegistration(msg.sender, signature, pubkey);
        validator.blsKey = pubkey;
        validator.isActive = true;
        _removeFromWhitelist(msg.sender);
        emit ValidatorRegistered(msg.sender, pubkey);
    }

    /**
     * @inheritdoc ICustomMetachainManager
     */
    function finalizeGenesis() external onlyOwner {
        // calling the library directly once fixes the coverage issue
        // https://github.com/foundry-rs/foundry/issues/4854#issuecomment-1528897219
        GenesisLib.finalize(_genesis);
        emit GenesisFinalized(_genesis.set().length);
    }

    /**
     * @inheritdoc ICustomMetachainManager
     */
    function enableStaking() external onlyOwner {
        _genesis.enableStaking();
        emit StakingEnabled();
    }

    /**
     * @inheritdoc ICustomMetachainManager
     */
    function onL2StateReceive(uint256 /*id*/, address sender, bytes calldata data) external {
        if (msg.sender != _exitHelper || sender != _childValidatorSet) revert Unauthorized("_exitHelper");
        if (bytes32(data[:32]) == _UNSTAKE_SIG) {
            (address validator, uint256 amount) = abi.decode(data[32:], (address, uint256));
            _unstake(validator, amount);
        }
    }

    /**
     * @inheritdoc ICustomMetachainManager
     */
    function genesisSet() external view returns (GenesisValidator[] memory) {
        return _genesis.set();
    }

    /**
     *
     * @inheritdoc ICustomMetachainManager
     */
    function getValidator(address validator_) external view returns (Validator memory) {
        return validators[validator_];
    }

    /**
     *
     * @inheritdoc ICustomMetachainManager
     */
    function addGenesisBalance(uint256 amount) external {
        require(amount > 0, "CustomMetachainManager: INVALID_AMOUNT");
        if (address(_rootERC20Predicate) == address(0)) {
            revert Unauthorized("CustomMetachainManager: UNDEFINED_ROOT_ERC20_PREDICATE");
        }

        IERC20 nativeTokenRoot = IERC20(_rootERC20Predicate.nativeTokenRoot());
        if (address(nativeTokenRoot) == address(0)) {
            revert Unauthorized("CustomMetachainManager: UNDEFINED_NATIVE_TOKEN_ROOT");
        }
        require(!_genesis.completed(), "CustomMetachainManager: GENESIS_SET_IS_ALREADY_FINALIZED");

        // we need to track EOAs as well in the genesis set, in order to be able to query genesisBalances mapping
        _genesis.insert(msg.sender, 0);
        // slither-disable-next-line reentrancy-benign
        genesisBalances[msg.sender] += amount;

        // lock native tokens on the root erc20 predicate
        nativeTokenRoot.safeTransferFrom(msg.sender, address(_rootERC20Predicate), amount);

        // slither-disable-next-line reentrancy-events
        emit GenesisBalanceAdded(msg.sender, amount);
    }

    function _onStake(address validator, uint256 amount) internal override onlyValidator(validator) {
        if (_genesis.gatheringGenesisValidators()) {
            _genesis.insert(validator, amount);
        } else if (_genesis.completed()) {
            _stateSender.syncState(_childValidatorSet, abi.encode(_STAKE_SIG, validator, amount));
        } else {
            revert Unauthorized("Wait for genesis");
        }
    }

    function _unstake(address validator, uint256 amount) internal {
        // slither-disable-next-line reentrancy-benign,reentrancy-events
        _stakeManager.releaseStakeOf(validator, amount);
        _removeIfValidatorUnstaked(validator);
    }

    function _verifyValidatorRegistration(
        address signer,
        uint256[2] calldata signature,
        uint256[4] calldata pubkey
    ) internal view {
        /// @dev signature verification succeeds if signature and pubkey are empty
        if (signature[0] == 0 && signature[1] == 0) revert InvalidSignature(signer);
        // slither-disable-next-line calls-loop
        (bool result, bool callSuccess) = _bls.verifySingle(signature, pubkey, _message(signer));
        if (!callSuccess || !result) revert InvalidSignature(signer);
    }

    /// @notice Message to sign for registration
    function _message(address signer) internal view returns (uint256[2] memory) {
        // slither-disable-next-line calls-loop
        return _bls.hashToPoint(domain, abi.encodePacked(signer, address(this), block.chainid));
    }

    function _addToWhitelist(address validator) internal {
        validators[validator].isWhitelisted = true;
        emit AddedToWhitelist(validator);
    }

    function _removeFromWhitelist(address validator) internal {
        validators[validator].isWhitelisted = false;
        emit RemovedFromWhitelist(validator);
    }

    function _removeIfValidatorUnstaked(address validator) internal {
        if (_stakeManager.stakeOf(validator, id) == 0) {
            validators[validator].isActive = false;
            emit ValidatorDeactivated(validator);
        }
    }

    // slither-disable-next-line unused-state,naming-convention
    uint256[48] private __gap;
}
