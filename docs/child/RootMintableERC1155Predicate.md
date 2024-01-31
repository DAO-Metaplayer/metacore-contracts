# RootMintableERC1155Predicate









## Methods

### DEPOSIT_BATCH_SIG

```solidity
function DEPOSIT_BATCH_SIG() external view returns (bytes32)
```






#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | bytes32 | undefined |

### DEPOSIT_SIG

```solidity
function DEPOSIT_SIG() external view returns (bytes32)
```






#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | bytes32 | undefined |

### MAP_TOKEN_SIG

```solidity
function MAP_TOKEN_SIG() external view returns (bytes32)
```






#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | bytes32 | undefined |

### WITHDRAW_BATCH_SIG

```solidity
function WITHDRAW_BATCH_SIG() external view returns (bytes32)
```






#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | bytes32 | undefined |

### WITHDRAW_SIG

```solidity
function WITHDRAW_SIG() external view returns (bytes32)
```






#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | bytes32 | undefined |

### childERC1155Predicate

```solidity
function childERC1155Predicate() external view returns (address)
```






#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### childTokenTemplate

```solidity
function childTokenTemplate() external view returns (address)
```






#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### deposit

```solidity
function deposit(contract IERC1155MetadataURI rootToken, uint256 tokenId, uint256 amount) external nonpayable
```

Function to deposit tokens from the depositor to themselves on the child chain



#### Parameters

| Name | Type | Description |
|---|---|---|
| rootToken | contract IERC1155MetadataURI | Address of the root token being deposited |
| tokenId | uint256 | Index of the NFT to deposit |
| amount | uint256 | Amount to deposit |

### depositBatch

```solidity
function depositBatch(contract IERC1155MetadataURI rootToken, address[] receivers, uint256[] tokenIds, uint256[] amounts) external nonpayable
```

Function to deposit tokens from the depositor to other addresses on the child chain



#### Parameters

| Name | Type | Description |
|---|---|---|
| rootToken | contract IERC1155MetadataURI | Address of the root token being deposited |
| receivers | address[] | Addresses of the receivers on the child chain |
| tokenIds | uint256[] | Indeices of the NFTs to deposit |
| amounts | uint256[] | Amounts to deposit |

### depositTo

```solidity
function depositTo(contract IERC1155MetadataURI rootToken, address receiver, uint256 tokenId, uint256 amount) external nonpayable
```

Function to deposit tokens from the depositor to another address on the child chain



#### Parameters

| Name | Type | Description |
|---|---|---|
| rootToken | contract IERC1155MetadataURI | Address of the root token being deposited |
| receiver | address | undefined |
| tokenId | uint256 | Index of the NFT to deposit |
| amount | uint256 | Amount to deposit |

### initialize

```solidity
function initialize(address newL2StateSender, address newStateReceiver, address newChildERC1155Predicate, address newChildTokenTemplate) external nonpayable
```

Initialization function for RootMintableERC1155Predicate

*Can only be called once.*

#### Parameters

| Name | Type | Description |
|---|---|---|
| newL2StateSender | address | Address of L2StateSender to send deposit information to |
| newStateReceiver | address | Address of StateReceiver to receive withdrawal information from |
| newChildERC1155Predicate | address | Address of child ERC1155 predicate to communicate with |
| newChildTokenTemplate | address | undefined |

### l2StateSender

```solidity
function l2StateSender() external view returns (contract IStateSender)
```






#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | contract IStateSender | undefined |

### mapToken

```solidity
function mapToken(contract IERC1155MetadataURI rootToken) external nonpayable returns (address childToken)
```

Function to be used for token mapping

*Called internally on deposit if token is not mapped already*

#### Parameters

| Name | Type | Description |
|---|---|---|
| rootToken | contract IERC1155MetadataURI | Address of the root token to map |

#### Returns

| Name | Type | Description |
|---|---|---|
| childToken | address | Address of the mapped child token |

### onERC1155BatchReceived

```solidity
function onERC1155BatchReceived(address, address, uint256[], uint256[], bytes) external nonpayable returns (bytes4)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |
| _1 | address | undefined |
| _2 | uint256[] | undefined |
| _3 | uint256[] | undefined |
| _4 | bytes | undefined |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | bytes4 | undefined |

### onERC1155Received

```solidity
function onERC1155Received(address, address, uint256, uint256, bytes) external nonpayable returns (bytes4)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |
| _1 | address | undefined |
| _2 | uint256 | undefined |
| _3 | uint256 | undefined |
| _4 | bytes | undefined |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | bytes4 | undefined |

### onStateReceive

```solidity
function onStateReceive(uint256, address sender, bytes data) external nonpayable
```

Function to be used for token withdrawals

*Can be extended to include other signatures for more functionality*

#### Parameters

| Name | Type | Description |
|---|---|---|
| _0 | uint256 | undefined |
| sender | address | undefined |
| data | bytes | undefined |

### rootTokenToChildToken

```solidity
function rootTokenToChildToken(address) external view returns (address)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### stateReceiver

```solidity
function stateReceiver() external view returns (address)
```






#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | address | undefined |

### supportsInterface

```solidity
function supportsInterface(bytes4 interfaceId) external view returns (bool)
```



*See {IERC165-supportsInterface}.*

#### Parameters

| Name | Type | Description |
|---|---|---|
| interfaceId | bytes4 | undefined |

#### Returns

| Name | Type | Description |
|---|---|---|
| _0 | bool | undefined |



## Events

### Initialized

```solidity
event Initialized(uint8 version)
```



*Triggered when the contract has been initialized or reinitialized.*

#### Parameters

| Name | Type | Description |
|---|---|---|
| version  | uint8 | undefined |

### L2MintableERC1155Deposit

```solidity
event L2MintableERC1155Deposit(address indexed rootToken, address indexed childToken, address depositor, address indexed receiver, uint256 tokenId, uint256 amount)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| rootToken `indexed` | address | undefined |
| childToken `indexed` | address | undefined |
| depositor  | address | undefined |
| receiver `indexed` | address | undefined |
| tokenId  | uint256 | undefined |
| amount  | uint256 | undefined |

### L2MintableERC1155DepositBatch

```solidity
event L2MintableERC1155DepositBatch(address indexed rootToken, address indexed childToken, address indexed depositor, address[] receivers, uint256[] tokenIds, uint256[] amounts)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| rootToken `indexed` | address | undefined |
| childToken `indexed` | address | undefined |
| depositor `indexed` | address | undefined |
| receivers  | address[] | undefined |
| tokenIds  | uint256[] | undefined |
| amounts  | uint256[] | undefined |

### L2MintableERC1155Withdraw

```solidity
event L2MintableERC1155Withdraw(address indexed rootToken, address indexed childToken, address withdrawer, address indexed receiver, uint256 tokenId, uint256 amount)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| rootToken `indexed` | address | undefined |
| childToken `indexed` | address | undefined |
| withdrawer  | address | undefined |
| receiver `indexed` | address | undefined |
| tokenId  | uint256 | undefined |
| amount  | uint256 | undefined |

### L2MintableERC1155WithdrawBatch

```solidity
event L2MintableERC1155WithdrawBatch(address indexed rootToken, address indexed childToken, address indexed withdrawer, address[] receivers, uint256[] tokenIds, uint256[] amounts)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| rootToken `indexed` | address | undefined |
| childToken `indexed` | address | undefined |
| withdrawer `indexed` | address | undefined |
| receivers  | address[] | undefined |
| tokenIds  | uint256[] | undefined |
| amounts  | uint256[] | undefined |

### L2MintableTokenMapped

```solidity
event L2MintableTokenMapped(address indexed rootToken, address indexed childToken)
```





#### Parameters

| Name | Type | Description |
|---|---|---|
| rootToken `indexed` | address | undefined |
| childToken `indexed` | address | undefined |



