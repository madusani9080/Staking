//SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.8.10;

import "./libs/BytesLib.sol";
import "./interfaces/IFeeRecipient.sol";
import "./interfaces/IDepositContract.sol";
import "./libs/StakingContractStorageLib.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";
import "./interfaces/ISanctionsOracle.sol";

/// @title Ethereum Staking Contract
/// @author Kiln
/// @notice You can use this contract to store validator keys and have users fund them and trigger deposits.
contract StakingContract {
    using StakingContractStorageLib for bytes32;

    uint256 internal constant EXECUTION_LAYER_SALT_PREFIX = 0;
    uint256 internal constant CONSENSUS_LAYER_SALT_PREFIX = 1;
    uint256 public constant SIGNATURE_LENGTH = 96;
    uint256 public constant PUBLIC_KEY_LENGTH = 48;
    uint256 public constant DEPOSIT_SIZE = 32 ether;
    // this is the equivalent of Uint256Lib.toLittleEndian64(DEPOSIT_SIZE / 1000000000 wei);
    uint256 constant DEPOSIT_SIZE_AMOUNT_LITTLEENDIAN64 =
        0x0040597307000000000000000000000000000000000000000000000000000000;
    uint256 internal constant BASIS_POINTS = 10_000;
    uint256 internal constant WITHDRAWAL_CREDENTIAL_PREFIX_01 =
        0x0100000000000000000000000000000000000000000000000000000000000000;

    error Forbidden();
    error InvalidFee();
    error Deactivated();
    error NoOperators();
    error InvalidCall();
    error Unauthorized();
    error DepositFailure();
    error DepositsStopped();
    error InvalidArgument();
    error UnsortedIndexes();
    error InvalidPublicKeys();
    error InvalidSignatures();
    error InvalidWithdrawer();
    error InvalidZeroAddress();
    error AlreadyInitialized();
    error InvalidDepositValue();
    error NotEnoughValidators();
    error InvalidValidatorCount();
    error DuplicateValidatorKey(bytes);
    error FundedValidatorDeletionAttempt();
    error OperatorLimitTooHigh(uint256 limit, uint256 keyCount);
    error MaximumOperatorCountAlreadyReached();
    error LastEditAfterSnapshot();
    error PublicKeyNotInContract();
    error AddressSanctioned(address sanctionedAccount);
    error AddressBlocked(address blockedAccount);

    event Deposit(address indexed caller, address indexed withdrawer, bytes publicKey, bytes signature);
    event ValidatorKeysAdded(uint256 indexed operatorIndex, bytes publicKeys, bytes signatures);
    event ValidatorKeyRemoved(uint256 indexed operatorIndex, bytes publicKey);
    event ChangedWithdrawer(bytes publicKey, address newWithdrawer);
    event ChangedOperatorLimit(uint256 operatorIndex, uint256 limit);
    event ChangedTreasury(address newTreasury);
    event ChangedGlobalFee(uint256 newGlobalFee);
    event ChangedOperatorFee(uint256 newOperatorFee);
    event ChangedAdmin(address newAdmin);
    event ChangedDepositsStopped(bool isStopped);
    event NewOperator(address operatorAddress, address feeRecipientAddress, uint256 index);
    event ChangedOperatorAddresses(uint256 operatorIndex, address operatorAddress, address feeRecipientAddress);
    event DeactivatedOperator(uint256 _operatorIndex);
    event ActivatedOperator(uint256 _operatorIndex);
    event ExitRequest(address caller, bytes pubkey);
    event ValidatorsEdited(uint256 blockNumber);
    event NewSanctionsOracle(address sanctionsOracle);
    event BeginOwnershipTransfer(address indexed previousAdmin, address indexed newAdmin);

    /// @notice Ensures an initialisation call has been called only once per _version value
    /// @param _version The current initialisation value
    modifier init(uint256 _version) {
        if (_version != StakingContractStorageLib.getVersion() + 1) {
            revert AlreadyInitialized();
        }

        StakingContractStorageLib.setVersion(_version);
        _;
    }

    /// @notice Ensures that the caller is the admin
    modifier onlyAdmin() {
        if (msg.sender != StakingContractStorageLib.getAdmin()) {
            revert Unauthorized();
        }

        _;
    }

    /// @notice Ensures that the caller is the admin or the operator
    modifier onlyActiveOperatorOrAdmin(uint256 _operatorIndex) {
        if (msg.sender == StakingContractStorageLib.getAdmin()) {
            _;
        } else {
            _onlyActiveOperator(_operatorIndex);
            _;
        }
    }

    /// @notice Ensures that the caller is the admin
    modifier onlyActiveOperator(uint256 _operatorIndex) {
        _onlyActiveOperator(_operatorIndex);
        _;
    }

    /// @notice Ensures that the caller is the operator fee recipient
    modifier onlyActiveOperatorFeeRecipient(uint256 _operatorIndex) {
        StakingContractStorageLib.OperatorInfo storage operatorInfo = StakingContractStorageLib.getOperators().value[
            _operatorIndex
        ];

        if (operatorInfo.deactivated) {
            revert Deactivated();
        }

        if (msg.sender != operatorInfo.feeRecipient) {
            revert Unauthorized();
        }

        _;
    }

    /// @notice Explicit deposit method using msg.sender
    /// @dev A multiple of 32 ETH should be sent
    function deposit() external payable {
        _deposit();
    }

    /// @notice Implicit deposit method
    /// @dev A multiple of 32 ETH should be sent
    /// @dev The withdrawer is set to the message sender address
    receive() external payable {
        _deposit();
    }

    /// @notice Fallback detection
    /// @dev Fails on any call that fallbacks
    fallback() external payable {
        revert InvalidCall();
    }

    function initialize_1(
        address _admin,
        address _treasury,
        address _depositContract,
        address _elDispatcher,
        address _clDispatcher,
        address _feeRecipientImplementation,
        uint256 _globalFee,
        uint256 _operatorFee,
        uint256 globalCommissionLimitBPS,
        uint256 operatorCommissionLimitBPS
    ) external init(1) {
        _checkAddress(_admin);
        StakingContractStorageLib.setAdmin(_admin);
        _checkAddress(_treasury);
        StakingContractStorageLib.setTreasury(_treasury);

        if (_globalFee > BASIS_POINTS) {
            revert InvalidFee();
        }
        StakingContractStorageLib.setGlobalFee(_globalFee);
        if (_operatorFee > BASIS_POINTS) {
            revert InvalidFee();
        }
        StakingContractStorageLib.setOperatorFee(_operatorFee);

        _checkAddress(_elDispatcher);
        StakingContractStorageLib.setELDispatcher(_elDispatcher);
        _checkAddress(_clDispatcher);
        StakingContractStorageLib.setCLDispatcher(_clDispatcher);
        _checkAddress(_depositContract);
        StakingContractStorageLib.setDepositContract(_depositContract);
        _checkAddress(_feeRecipientImplementation);
        StakingContractStorageLib.setFeeRecipientImplementation(_feeRecipientImplementation);
        initialize_2(globalCommissionLimitBPS, operatorCommissionLimitBPS);
    }

    function initialize_2(uint256 globalCommissionLimitBPS, uint256 operatorCommissionLimitBPS) public init(2) {
        if (globalCommissionLimitBPS > BASIS_POINTS) {
            revert InvalidFee();
        }
        StakingContractStorageLib.setGlobalCommissionLimit(globalCommissionLimitBPS);
        if (operatorCommissionLimitBPS > BASIS_POINTS) {
            revert InvalidFee();
        }
        StakingContractStorageLib.setOperatorCommissionLimit(operatorCommissionLimitBPS);
    }

    /// @notice Changes the sanctions oracle address
    /// @param _sanctionsOracle New sanctions oracle address
    /// @dev If the address is address(0), the sanctions oracle checks are skipped
    function setSanctionsOracle(address _sanctionsOracle) external onlyAdmin {
        StakingContractStorageLib.setSanctionsOracle(_sanctionsOracle);
        emit NewSanctionsOracle(_sanctionsOracle);
    }

    /// @notice Get the sanctions oracle address
    /// @notice If the address is address(0), the sanctions oracle checks are skipped
    /// @return sanctionsOracle The sanctions oracle address
    function getSanctionsOracle() external view returns (address) {
        return StakingContractStorageLib.getSanctionsOracle();
    }

    /// @notice Retrieve system admin
    function getAdmin() external view returns (address) {
        return StakingContractStorageLib.getAdmin();
    }

    /// @notice Set new treasury
    /// @dev Only callable by admin
    /// @param _newTreasury New Treasury address
    function setTreasury(address _newTreasury) external onlyAdmin {
        emit ChangedTreasury(_newTreasury);
        StakingContractStorageLib.setTreasury(_newTreasury);
    }

    /// @notice Retrieve system treasury
    function getTreasury() external view returns (address) {
        return StakingContractStorageLib.getTreasury();
    }

    /// @notice Retrieve the global fee
    function getGlobalFee() external view returns (uint256) {
        return StakingContractStorageLib.getGlobalFee();
    }

    /// @notice Retrieve the operator fee
    function getOperatorFee() external view returns (uint256) {
        return StakingContractStorageLib.getOperatorFee();
    }

    /// @notice Compute the Execution Layer Fee recipient address for a given validator public key
    /// @param _publicKey Validator to get the recipient
    function getELFeeRecipient(bytes calldata _publicKey) external view returns (address) {
        return _getDeterministicReceiver(_publicKey, EXECUTION_LAYER_SALT_PREFIX);
    }

    /// @notice Compute the Consensus Layer Fee recipient address for a given validator public key
    /// @param _publicKey Validator to get the recipient
    function getCLFeeRecipient(bytes calldata _publicKey) external view returns (address) {
        return _getDeterministicReceiver(_publicKey, CONSENSUS_LAYER_SALT_PREFIX);
    }

    /// @notice Retrieve the Execution & Consensus Layer Fee operator recipient for a given public key
    function getOperatorFeeRecipient(bytes32 pubKeyRoot) external view returns (address) {
        if (StakingContractStorageLib.getOperatorIndexPerValidator().value[pubKeyRoot].enabled == false) {
            revert PublicKeyNotInContract();
        }
        return
            StakingContractStorageLib
                .getOperators()
                .value[StakingContractStorageLib.getOperatorIndexPerValidator().value[pubKeyRoot].operatorIndex]
                .feeRecipient;
    }

    /// @notice Retrieve withdrawer of public key
    /// @notice In case the validator is not enabled, it will return address(0)
    /// @param _publicKey Public Key to check
    function getWithdrawer(bytes calldata _publicKey) external view returns (address) {
        return _getWithdrawer(_getPubKeyRoot(_publicKey));
    }

    /// @notice Retrieve withdrawer of public key root
    /// @notice In case the validator is not enabled, it will return address(0)
    /// @notice In case the owner of the validator is sanctioned, it will revert
    /// @param _publicKeyRoot Hash of the public key
    function getWithdrawerFromPublicKeyRoot(bytes32 _publicKeyRoot) external view returns (address) {
        address withdrawer = _getWithdrawer(_publicKeyRoot);
        if (withdrawer == address(0)) {
            return address(0);
        }
        address sanctionsOracle = StakingContractStorageLib.getSanctionsOracle();
        if (sanctionsOracle != address(0)) {
            if (ISanctionsOracle(sanctionsOracle).isSanctioned(withdrawer)) {
                revert AddressSanctioned(withdrawer);
            }
        }
        return withdrawer;
    }

    /// @notice Retrieve whether the validator exit has been requested
    /// @notice In case the validator is not enabled, it will return false
    /// @param _publicKeyRoot Public Key Root to check
    function getExitRequestedFromRoot(bytes32 _publicKeyRoot) external view returns (bool) {
        return _getExitRequest(_publicKeyRoot);
    }

    /// @notice Return true if the validator already went through the exit logic
    /// @notice In case the validator is not enabled, it will return false
    /// @param _publicKeyRoot Public Key Root of the validator
    function getWithdrawnFromPublicKeyRoot(bytes32 _publicKeyRoot) external view returns (bool) {
        return StakingContractStorageLib.getWithdrawnMap().value[_publicKeyRoot];
    }

    /// @notice Retrieve the enabled status of public key root, true if the key is in the contract
    /// @param _publicKeyRoot Hash of the public key
    function getEnabledFromPublicKeyRoot(bytes32 _publicKeyRoot) external view returns (bool) {
        return StakingContractStorageLib.getOperatorIndexPerValidator().value[_publicKeyRoot].enabled;
    }

    /// @notice Allows the CLDispatcher to signal a validator went through the exit logic
    /// @param _publicKeyRoot Public Key Root of the validator
    function toggleWithdrawnFromPublicKeyRoot(bytes32 _publicKeyRoot) external {
        if (msg.sender != StakingContractStorageLib.getCLDispatcher()) {
            revert Unauthorized();
        }
        StakingContractStorageLib.getWithdrawnMap().value[_publicKeyRoot] = true;
    }

    /// @notice Returns false if the users can deposit, true if deposits are stopped
    function getDepositsStopped() external view returns (bool) {
        return StakingContractStorageLib.getDepositStopped();
    }

    /// @notice Retrieve operator details
    /// @param _operatorIndex Operator index
    function getOperator(uint256 _operatorIndex)
        external
        view
        returns (
            address operatorAddress,
            address feeRecipientAddress,
            uint256 limit,
            uint256 keys,
            uint256 funded,
            uint256 available,
            bool deactivated
        )
    {
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        if (_operatorIndex < operators.value.length) {
            StakingContractStorageLib.ValidatorsFundingInfo memory _operatorInfo = StakingContractStorageLib
                .getValidatorsFundingInfo(_operatorIndex);
            StakingContractStorageLib.OperatorInfo storage _operator = operators.value[_operatorIndex];

            (operatorAddress, feeRecipientAddress, limit, keys, deactivated) = (
                _operator.operator,
                _operator.feeRecipient,
                _operator.limit,
                _operator.publicKeys.length,
                _operator.deactivated
            );
            (funded, available) = (_operatorInfo.funded, _operatorInfo.availableKeys);
        }
    }

    /// @notice Get details about a validator
    /// @param _operatorIndex Index of the operator running the validator
    /// @param _validatorIndex Index of the validator
    function getValidator(uint256 _operatorIndex, uint256 _validatorIndex)
        external
        view
        returns (
            bytes memory publicKey,
            bytes memory signature,
            address withdrawer,
            bool funded
        )
    {
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        publicKey = operators.value[_operatorIndex].publicKeys[_validatorIndex];
        signature = operators.value[_operatorIndex].signatures[_validatorIndex];
        withdrawer = _getWithdrawer(_getPubKeyRoot(publicKey));
        funded = _validatorIndex < StakingContractStorageLib.getValidatorsFundingInfo(_operatorIndex).funded;
    }

    /// @notice Get the total available keys that are ready to be used for deposits
    function getAvailableValidatorCount() external view returns (uint256) {
        return StakingContractStorageLib.getTotalAvailableValidators();
    }

    /// @notice Set new admin
    /// @dev Only callable by admin
    /// @param _newAdmin New Administrator address
    function transferOwnership(address _newAdmin) external onlyAdmin {
        StakingContractStorageLib.setPendingAdmin(_newAdmin);
        emit BeginOwnershipTransfer(msg.sender, _newAdmin);
    }

    /// @notice New admin must accept its role by calling this method
    /// @dev Only callable by new admin
    function acceptOwnership() external {
        address newAdmin = StakingContractStorageLib.getPendingAdmin();

        if (msg.sender != newAdmin) {
            revert Unauthorized();
        }
        StakingContractStorageLib.setAdmin(newAdmin);
        StakingContractStorageLib.setPendingAdmin(address(0));
        emit ChangedAdmin(newAdmin);
    }

    /// @notice Get the new admin's address previously set for an ownership transfer
    function getPendingAdmin() external view returns (address) {
        return StakingContractStorageLib.getPendingAdmin();
    }

    /// @notice Add new operator
    /// @dev Only callable by admin
    /// @param _operatorAddress Operator address allowed to add / remove validators
    /// @param _feeRecipientAddress Privileged operator address used to manage rewards and operator addresses
    function addOperator(address _operatorAddress, address _feeRecipientAddress) external onlyAdmin returns (uint256) {
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        StakingContractStorageLib.OperatorInfo memory newOperator;

        if (operators.value.length == 1) {
            revert MaximumOperatorCountAlreadyReached();
        }
        newOperator.operator = _operatorAddress;
        newOperator.feeRecipient = _feeRecipientAddress;
        operators.value.push(newOperator);
        uint256 operatorIndex = operators.value.length - 1;
        emit NewOperator(_operatorAddress, _feeRecipientAddress, operatorIndex);
        return operatorIndex;
    }

    /// @notice Set new operator addresses (operations and reward management)
    /// @dev Only callable by fee recipient address manager
    /// @param _operatorIndex Index of the operator to update
    /// @param _operatorAddress New operator address for operations management
    /// @param _feeRecipientAddress New operator address for reward management
    function setOperatorAddresses(
        uint256 _operatorIndex,
        address _operatorAddress,
        address _feeRecipientAddress
    ) external onlyActiveOperatorFeeRecipient(_operatorIndex) {
        _checkAddress(_operatorAddress);
        _checkAddress(_feeRecipientAddress);
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();

        operators.value[_operatorIndex].operator = _operatorAddress;
        operators.value[_operatorIndex].feeRecipient = _feeRecipientAddress;
        emit ChangedOperatorAddresses(_operatorIndex, _operatorAddress, _feeRecipientAddress);
    }

    /// @notice Set operator staking limits
    /// @dev Only callable by admin
    /// @dev Limit should not exceed the validator key count of the operator
    /// @dev Keys should be registered before limit is increased
    /// @dev Allows all keys to be verified by the system admin before limit is increased
    /// @param _operatorIndex Operator Index
    /// @param _limit New staking limit
    /// @param _snapshot Block number at which verification was done
    function setOperatorLimit(
        uint256 _operatorIndex,
        uint256 _limit,
        uint256 _snapshot
    ) external onlyAdmin {
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        if (operators.value[_operatorIndex].deactivated) {
            revert Deactivated();
        }
        uint256 publicKeyCount = operators.value[_operatorIndex].publicKeys.length;
        if (publicKeyCount < _limit) {
            revert OperatorLimitTooHigh(_limit, publicKeyCount);
        }
        if (
            operators.value[_operatorIndex].limit < _limit &&
            StakingContractStorageLib.getLastValidatorEdit() > _snapshot
        ) {
            revert LastEditAfterSnapshot();
        }
        operators.value[_operatorIndex].limit = _limit;
        _updateAvS
