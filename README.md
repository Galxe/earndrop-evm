# EVM Vesting Earndrop

**EVM Vesting Earndrop** 是一个基于以太坊的智能合约项目，支持代币的分阶段发放和空投功能。该项目使用 [Foundry](https://book.getfoundry.sh/) 作为开发工具，提供高效的测试、部署和格式化工具。

## 功能

- **分阶段发放 (Vesting)**: 支持按时间段分发代币。
- **空投 (Airdrop)**: 基于 Merkle 树验证的空投功能。
- **权限管理**: 提供灵活的权限控制，包括管理员和签名者角色。

## 技术栈

- **Solidity**: 智能合约开发语言。
- **Foundry**: 高效的以太坊开发工具链。
- **OpenZeppelin**: 提供安全的智能合约库。

## 安装

确保已安装以下工具：

- [Foundry](https://book.getfoundry.sh/getting-started/installation.html)
- [Node.js](https://nodejs.org/) (可选，用于前端集成)

克隆项目并安装依赖：

```shell
$ git clone https://github.com/your-repo/evm_vesting_earndrop.git
$ cd evm_vesting_earndrop
$ forge install
```

## 使用

### 构建项目

```shell
$ forge build
```

### 运行测试

```shell
$ forge test
```


### 部署合约

使用 `Makefile` 提供的命令部署合约：

```shell
$ make deploy_vesting_earndrop
```

### 格式化代码

```shell
$ forge fmt
```



## 合约权限说明

- **Owner**: 合约的所有者，拥有以下权限：
  - 设置签名者地址 (`setSigner`)。
  - 设置资金管理员地址 (`setTreasurer`)。
- **Admin**: 管理特定的 Earndrop，包括激活、撤销。
- **安全限制**:
  - 签名者和资金管理员地址不能为零地址。
  - 未经授权的操作将抛出 `Unauthorized` 错误。

## 目录结构

```
├── src
│   └── VestingEarndrop.sol       # 主合约
├── test
│   └── VestingEarndrop.t.sol     # 测试文件
├── script
│   └── Deploy.s.sol              # 部署脚本
├── Makefile                      # 构建和部署命令
├── foundry.toml                  # Foundry 配置文件
└── README.md                     # 项目说明
```

## 文档

- [Foundry 官方文档](https://book.getfoundry.sh/)
- [OpenZeppelin 文档](https://docs.openzeppelin.com/)

## 贡献

欢迎提交 Issue 或 Pull Request 来改进本项目。

