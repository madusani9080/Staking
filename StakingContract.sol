
    /// @notice Withdraw the Consensus Layer Fee for given validators public keys
    /// @dev Funds are sent to the withdrawer account
    /// @dev This method is public on purpose
    /// @param _publicKeys Validators to withdraw Consensus Layer Fees from
    function batchWithdrawCLFee(bytes calldata _publicKeys) external {
        if (_publicKeys.length % PUBLIC_KEY_LENGTH != 0) {
            revert InvalidPublicKeys();
        }
        for (uint256 i = 0; i < _publicKeys.length; ) {
            bytes memory publicKey = BytesLib.slice(_publicKeys, i, PUBLIC_KEY_LENGTH);
            _onlyWithdrawerOrAdmin(publicKey);
            _deployAndWithdraw(publicKey, CONSENSUS_LAYER_SALT_PREFIX, StakingContractStorageLib.getCLDispatcher());
            unchecked {
                i += PUBLIC_KEY_LENGTH;
            }
        }
    }

    /// @notice Withdraw both Consensus and Execution Layer Fees for given validators public keys
    /// @dev Funds are sent to the withdrawer account
    /// @param _publicKeys Validators to withdraw fees from
    function batchWithdraw(bytes calldata _publicKeys) external {
        if (_publicKeys.length % PUBLIC_KEY_LENGTH != 0) {
            revert InvalidPublicKeys();
        }
        for (uint256 i = 0; i < _publicKeys.length; ) {
            bytes memory publicKey = BytesLib.slice(_publicKeys, i, PUBLIC_KEY_LENGTH);
            _onlyWithdrawerOrAdmin(publicKey);
            _deployAndWithdraw(publicKey, EXECUTION_LAYER_SALT_PREFIX, StakingContractStorageLib.getELDispatcher());
            _deployAndWithdraw(publicKey, CONSENSUS_LAYER_SALT_PREFIX, StakingContractStorageLib.getCLDispatcher());
            unchecked {
                i += PUBLIC_KEY_LENGTH;
            }
        }
    }

    /// @notice Withdraw the Execution Layer Fee for a given validator public key
    /// @dev Funds are sent to the withdrawer account
    /// @param _publicKey Validator to withdraw Execution Layer Fees from
    function withdrawELFee(bytes calldata _publicKey) external {
        _onlyWithdrawerOrAdmin(_publicKey);
        _deployAndWithdraw(_publicKey, EXECUTION_LAYER_SALT_PREFIX, StakingContractStorageLib.getELDispatcher());
    }

    /// @notice Withdraw the Consensus Layer Fee for a given validator public key
    /// @dev Funds are sent to the withdrawer account
    /// @param _publicKey Validator to withdraw Consensus Layer Fees from
    function withdrawCLFee(bytes calldata _publicKey) external {
        _onlyWithdrawerOrAdmin(_publicKey);
        _deployAndWithdraw(_publicKey, CONSENSUS_LAYER_SALT_PREFIX, StakingContractStorageLib.getCLDispatcher());
    }

    /// @notice Withdraw both Consensus and Execution Layer Fee for a given validator public key
    /// @dev Reverts if any is null
    /// @param _publicKey Validator to withdraw Execution and Consensus Layer Fees from
    function withdraw(bytes calldata _publicKey) external {
        _onlyWithdrawerOrAdmin(_publicKey);
        _deployAndWithdraw(_publicKey, EXECUTION_LAYER_SALT_PREFIX, StakingContractStorageLib.getELDispatcher());
        _deployAndWithdraw(_publicKey, CONSENSUS_LAYER_SALT_PREFIX, StakingContractStorageLib.getCLDispatcher());
    }

    function requestValidatorsExit(bytes calldata _publicKeys) external {
        _revertIfSanctioned(msg.sender);
        _requestExits(_publicKeys, msg.sender);
    }

    /// @notice Utility to stop or allow deposits
    function setDepositsStopped(bool val) external onlyAdmin {
        emit ChangedDepositsStopped(val);
        StakingContractStorageLib.setDepositStopped(val);
    }

function _depositValidatorsOfOperator(uint256 _operatorIndex, uint256 _validatorCount) internal {
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        StakingContractStorageLib.OperatorInfo storage operator = operators.value[_operatorIndex];
        StakingContractStorageLib.ValidatorsFundingInfo memory vfi = StakingContractStorageLib.getValidatorsFundingInfo(
            _operatorIndex
        );

        for (uint256 i = vfi.funded; i < vfi.funded + _validatorCount; ) {
            bytes memory publicKey = operator.publicKeys[i];
            bytes memory signature = operator.signatures[i];
            address consensusLayerRecipient = _getDeterministicReceiver(publicKey, CONSENSUS_LAYER_SALT_PREFIX);
            bytes32 withdrawalCredentials = _addressToWithdrawalCredentials(consensusLayerRecipient);
            bytes32 pubkeyRoot = _getPubKeyRoot(publicKey);
            _depositValidator(publicKey, pubkeyRoot, signature, withdrawalCredentials);
            StakingContractStorageLib.getWithdrawers().value[pubkeyRoot] = msg.sender;
            emit Deposit(msg.sender, msg.sender, publicKey, signature);
            unchecked {
                ++i;
            }
        }

        StakingContractStorageLib.setValidatorsFundingInfo(
            _operatorIndex,
            uint32(vfi.availableKeys - _validatorCount),
            uint32(vfi.funded + _validatorCount)
        );
    }

    /// @notice Internal utility to deposit a public key, its signature and 32 ETH to the consensus layer
    /// @param _publicKey The Public Key to deposit
    /// @param _signature The Signature to deposit
    /// @param _withdrawalCredentials The Withdrawal Credentials to deposit
    function _depositValidator(
        bytes memory _publicKey,
        bytes32 _pubkeyRoot,
        bytes memory _signature,
        bytes32 _withdrawalCredentials
    ) internal {
        bytes32 signatureRoot = sha256(
            abi.encodePacked(
                sha256(BytesLib.slice(_signature, 0, 64)),
                sha256(abi.encodePacked(BytesLib.slice(_signature, 64, SIGNATURE_LENGTH - 64), bytes32(0)))
            )
        );

        bytes32 depositDataRoot = sha256(
            abi.encodePacked(
                sha256(abi.encodePacked(_pubkeyRoot, _withdrawalCredentials)),
                sha256(abi.encodePacked(DEPOSIT_SIZE_AMOUNT_LITTLEENDIAN64, signatureRoot))
            )
        );

        uint256 targetBalance = address(this).balance - DEPOSIT_SIZE;

        IDepositContract(StakingContractStorageLib.getDepositContract()).deposit{value: DEPOSIT_SIZE}(
            _publicKey,
            abi.encodePacked(_withdrawalCredentials),
            _signature,
            depositDataRoot
        );

        if (address(this).balance != targetBalance) {
            revert DepositFailure();
        }
    }

    function _depositOnOneOperator(uint256 _depositCount, uint256 _totalAvailableValidators) internal {
        StakingContractStorageLib.setTotalAvailableValidators(_totalAvailableValidators - _depositCount);
        _depositValidatorsOfOperator(0, _depositCount);
    }

    function _deposit() internal {
        if (StakingContractStorageLib.getDepositStopped()) {
            revert DepositsStopped();
        }
        _revertIfSanctionedOrBlocked(msg.sender);
        if (msg.value == 0 || msg.value % DEPOSIT_SIZE != 0) {
            revert InvalidDepositValue();
        }
        uint256 totalAvailableValidators = StakingContractStorageLib.getTotalAvailableValidators();
        uint256 depositCount = msg.value / DEPOSIT_SIZE;
        if (depositCount > totalAvailableValidators) {
            revert NotEnoughValidators();
        }
        StakingContractStorageLib.OperatorsSlot storage operators = StakingContractStorageLib.getOperators();
        if (operators.value.length == 0) {
            revert NoOperators();
        }
        _depositOnOneOperator(depositCount, totalAvailableValidators);
    }

    /// @notice Internal utility to compute the receiver deterministic address
    /// @param _publicKey Public Key assigned to the receiver
    /// @param _prefix Prefix used to generate multiple receivers per public key
    function _getDeterministicReceiver(bytes memory _publicKey, uint256 _prefix) internal view returns (address) {
        bytes32 publicKeyRoot = _getPubKeyRoot(_publicKey);
        bytes32 salt = sha256(abi.encodePacked(_prefix, publicKeyRoot));
        address implementation = StakingContractStorageLib.getFeeRecipientImplementation();
        return Clones.predictDeterministicAddress(implementation, salt);
    }

    /// @notice Internal utility to deploy and withdraw the fees from a receiver
    /// @param _publicKey Public Key assigned to the receiver
    /// @param _prefix Prefix used to generate multiple receivers per public key
    /// @param _dispatcher Address of the dispatcher contract
    function _deployAndWithdraw(
        bytes memory _publicKey,
        uint256 _prefix,
        address _dispatcher
    ) internal {
        bytes32 publicKeyRoot = _getPubKeyRoot(_publicKey);
        _revertIfSanctioned(msg.sender);
        bytes32 feeRecipientSalt = sha256(abi.encodePacked(_prefix, publicKeyRoot));
        address implementation = StakingContractStorageLib.getFeeRecipientImplementation();
        address feeRecipientAddress = Clones.predictDeterministicAddress(implementation, feeRecipientSalt);
        if (feeRecipientAddress.code.length == 0) {
            Clones.cloneDeterministic(implementation, feeRecipientSalt);
            IFeeRecipient(feeRecipientAddress).init(_dispatcher, publicKeyRoot);
        }
        IFeeRecipient(feeRecipientAddress).withdraw();
    }

    function _checkAddress(address _address) internal pure {
        if (_address == address(0)) {
            revert InvalidZeroAddress();
        }
    }

    function _revertIfSanctionedOrBlocked(address account) internal view {
        address sanctionsOracle = StakingContractStorageLib.getSanctionsOracle();
        if (sanctionsOracle != address(0)) {
            if (ISanctionsOracle(sanctionsOracle).isSanctioned(account)) {
                revert AddressSanctioned(account);
            }
        }
        if (StakingContractStorageLib.getBlocklist().value[account]) {
            revert AddressBlocked(account);
        }
    }

    function _revertIfSanctioned(address account) internal view {
        address sanctionsOracle = StakingContractStorageLib.getSanctionsOracle();
        if (sanctionsOracle != address(0)) {
            if (ISanctionsOracle(sanctionsOracle).isSanctioned(account)) {
                revert AddressSanctioned(account);
            }
        }
    }
