package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"ibc-cosmos-ethereum-test/e2e/interchaintestv8/e2esuite"
	"ibc-cosmos-ethereum-test/e2e/interchaintestv8/operator"
	"ibc-cosmos-ethereum-test/e2e/interchaintestv8/testvalues"
	"ibc-cosmos-ethereum-test/e2e/interchaintestv8/types/erc20"
	"ibc-cosmos-ethereum-test/e2e/interchaintestv8/types/ics02client"
	"ibc-cosmos-ethereum-test/e2e/interchaintestv8/types/ics20transfer"
	"ibc-cosmos-ethereum-test/e2e/interchaintestv8/types/ics26router"
	"ibc-cosmos-ethereum-test/e2e/interchaintestv8/types/sp1ics07tendermint"

	"github.com/strangelove-ventures/interchaintest/v8/chain/ethereum"
	"github.com/strangelove-ventures/interchaintest/v8/ibc"

	ethcommon "github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"

	transfertypes "github.com/cosmos/ibc-go/v8/modules/apps/transfer/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	channeltypes "github.com/cosmos/ibc-go/v8/modules/core/04-channel/types"
	commitmenttypes "github.com/cosmos/ibc-go/v8/modules/core/23-commitment/types"
	ibchost "github.com/cosmos/ibc-go/v8/modules/core/24-host"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	mock "github.com/cosmos/ibc-go/v8/modules/light-clients/00-mock"
	ibctesting "github.com/cosmos/ibc-go/v8/testing"

	"github.com/stretchr/testify/suite"
)

type EthereumCosmosIBCTestSuite struct {
	e2esuite.TestSuite

	// The private key of a test account
	key *ecdsa.PrivateKey
	// The private key of the faucet account of interchaintest
	faucet   *ecdsa.PrivateKey
	deployer ibc.Wallet

	contractAddresses e2esuite.DeployedContracts

	sp1Ics07Contract   *sp1ics07tendermint.Contract
	ics02Contract      *ics02client.Contract
	ics26Contract      *ics26router.Contract
	ics20Contract      *ics20transfer.Contract
	erc20Contract      *erc20.Contract
	escrowContractAddr ethcommon.Address

	ethClientID  string
	simdClientID string
}

func (s *EthereumCosmosIBCTestSuite) SetupSuite(ctx context.Context) {
	s.TestSuite.SetupSuite(ctx)

	eth, simd := s.ChainA, s.ChainB

	s.Run("Set up environment", func() {
		err := os.Chdir("../..")
		s.Require().NoError(err)

		// Set test account
		s.key, err = crypto.GenerateKey()
		s.Require().NoError(err)
		testKeyAddress := crypto.PubkeyToAddress(s.key.PublicKey).Hex()

		// Set deployer
		s.deployer, err = eth.BuildWallet(ctx, "deployer", "")
		s.Require().NoError(err)
		deployerAddress := s.deployer.FormattedAddress()

		// Set operator
		operatorKey, err := crypto.GenerateKey()
		s.Require().NoError(err)
		operatorAddress := crypto.PubkeyToAddress(operatorKey.PublicKey).Hex()

		// get faucet private key from string
		faucetPk := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
		s.faucet, err = crypto.HexToECDSA(faucetPk)
		s.Require().NoError(err)

		os.Setenv("PRIVATE_KEY", hex.EncodeToString(crypto.FromECDSA(operatorKey)))
		os.Setenv("RPC_URL", eth.GetHostRPCAddress())
		os.Setenv("TENDERMINT_RPC_URL", simd.GetHostRPCAddress())
		os.Setenv("SP1_PROVER", "mock")

		s.Require().NoError(eth.SendFunds(ctx, "faucet", ibc.WalletAmount{
			Amount:  sdkmath.NewInt(2 * ethereum.ETHER),
			Address: testKeyAddress,
		}))
		s.Require().NoError(eth.SendFunds(ctx, "faucet", ibc.WalletAmount{
			Amount:  sdkmath.NewInt(2 * ethereum.ETHER),
			Address: deployerAddress,
		}))
		s.Require().NoError(eth.SendFunds(ctx, "faucet", ibc.WalletAmount{
			Amount:  sdkmath.NewInt(2 * ethereum.ETHER),
			Address: operatorAddress,
		}))
	})

	s.Run("Deploy contracts", func() {
		s.Require().NoError(operator.RunGenesis(
			"--trust-level", testvalues.DefaultTrustLevel.String(),
			"--trusting-period", strconv.Itoa(testvalues.DefaultTrustPeriod),
			"-o", testvalues.Sp1GenesisFilePath,
		))

		stdout, stderr, err := eth.ForgeScript(ctx, s.deployer.KeyName(), ethereum.ForgeScriptOpts{
			ContractRootDir:  ".",
			SolidityContract: "scripts/MockE2ETestDeploy.s.sol",
			RawOptions: []string{
				"--json",
				"--sender", s.deployer.FormattedAddress(), // This, combined with the keyname, makes msg.sender the deployer
			},
		})
		s.Require().NoError(err, fmt.Sprintf("error deploying contracts: \nstderr: %s\nstdout: %s", stderr, stdout))

		ethClient, err := ethclient.Dial(eth.GetHostRPCAddress())
		s.Require().NoError(err)

		s.contractAddresses = s.GetEthContractsFromDeployOutput(string(stdout))
		s.sp1Ics07Contract, err = sp1ics07tendermint.NewContract(ethcommon.HexToAddress(s.contractAddresses.Ics02Client), ethClient)
		s.Require().NoError(err)
		s.ics02Contract, err = ics02client.NewContract(ethcommon.HexToAddress(s.contractAddresses.Ics02Client), ethClient)
		s.Require().NoError(err)
		s.ics26Contract, err = ics26router.NewContract(ethcommon.HexToAddress(s.contractAddresses.Ics26Router), ethClient)
		s.Require().NoError(err)
		s.ics20Contract, err = ics20transfer.NewContract(ethcommon.HexToAddress(s.contractAddresses.Ics20Transfer), ethClient)
		s.Require().NoError(err)
		s.erc20Contract, err = erc20.NewContract(ethcommon.HexToAddress(s.contractAddresses.Erc20), ethClient)
		s.Require().NoError(err)
		s.escrowContractAddr = ethcommon.HexToAddress(s.contractAddresses.Escrow)
	})

	s.T().Cleanup(func() {
		_ = os.Remove(testvalues.Sp1GenesisFilePath)
	})

	s.Run("Fund address with ERC20", func() {
		tx, err := s.erc20Contract.Transfer(s.GetTransactOpts(s.faucet), crypto.PubkeyToAddress(s.key.PublicKey), big.NewInt(testvalues.InitialBalance))
		s.Require().NoError(err)

		_ = s.GetTxReceipt(ctx, eth, tx.Hash())
	})

	_, simdRelayerUser := s.GetRelayerUsers(ctx)
	s.Run("Add client on Cosmos chain", func() {
		ethHeight, err := eth.Height(ctx)
		s.Require().NoError(err)

		clientState := mock.ClientState{
			LatestHeight: clienttypes.NewHeight(1, uint64(ethHeight)),
		}
		clientStateAny, err := clienttypes.PackClientState(&clientState)
		s.Require().NoError(err)
		consensusState := mock.ConsensusState{
			Timestamp: uint64(time.Now().UnixNano()),
		}
		consensusStateAny, err := clienttypes.PackConsensusState(&consensusState)
		s.Require().NoError(err)

		res, err := s.BroadcastMessages(ctx, simd, simdRelayerUser, 200_000, &clienttypes.MsgCreateClient{
			ClientState:      clientStateAny,
			ConsensusState:   consensusStateAny,
			Signer:           simdRelayerUser.FormattedAddress(),
			CounterpartyId:   "",
			MerklePathPrefix: nil,
		})
		s.Require().NoError(err)

		s.simdClientID, err = ibctesting.ParseClientIDFromEvents(res.Events)
		s.Require().NoError(err)
		s.Require().Equal("00-mock-0", s.simdClientID)
	})

	s.Run("Add client and counterparty on Ethereum", func() {
		counterpartyInfo := ics02client.IICS02ClientMsgsCounterpartyInfo{
			ClientId:     s.simdClientID,
			MerklePrefix: [][]byte{[]byte(ibcexported.StoreKey), []byte("")},
		}
		lightClientAddress := ethcommon.HexToAddress(s.contractAddresses.Ics07Tendermint)
		tx, err := s.ics02Contract.AddClient(s.GetTransactOpts(s.key), ibcexported.Tendermint, counterpartyInfo, lightClientAddress)
		s.Require().NoError(err)

		receipt := s.GetTxReceipt(ctx, eth, tx.Hash())
		event, err := e2esuite.GetEvmEvent(receipt, s.ics02Contract.ParseICS02ClientAdded)
		s.Require().NoError(err)
		s.Require().Equal(ibctesting.FirstClientID, event.ClientId)
		s.Require().Equal(s.simdClientID, event.CounterpartyInfo.ClientId)
		s.ethClientID = event.ClientId
	})

	s.Run("Register counterparty on Comsos chain", func() {
		// NOTE: This is the mock client on the Cosmos chain, so the prefix need not be valid
		merklePathPrefix := commitmenttypes.NewMerklePath([]byte{0x1})

		_, err := s.BroadcastMessages(ctx, simd, simdRelayerUser, 200_000, &clienttypes.MsgProvideCounterparty{
			ClientId:         s.simdClientID,
			CounterpartyId:   s.ethClientID,
			MerklePathPrefix: &merklePathPrefix,
			Signer:           simdRelayerUser.FormattedAddress(),
		})
		s.Require().NoError(err)
	})

}

func TestEthereumCosmosIbc(t *testing.T) {
	suite.Run(t, new(EthereumCosmosIBCTestSuite))
}

func (s *EthereumCosmosIBCTestSuite) TestDeploy() {
	ctx := context.Background()

	s.SetupSuite(ctx)

	_, simd := s.ChainA, s.ChainB

	s.Require().True(s.Run("Verify SP1 Client", func() {
		clientState, err := s.sp1Ics07Contract.GetClientState(nil)
		s.Require().NoError(err)

		stakingParams, err := simd.StakingQueryParams(ctx)
		s.Require().NoError(err)

		s.Require().Equal(simd.Config().ChainID, clientState.ChainId)
		s.Require().Equal(uint32(stakingParams.UnbondingTime.Seconds()), clientState.UnbondingPeriod)
		s.Require().False(clientState.IsFrozen)
		s.Require().Equal(uint32(1), clientState.LatestHeight.RevisionNumber)
		s.Require().Greater(clientState.LatestHeight.RevisionHeight, uint32(0))
	}))
}

// TestICS20TransferERC20TokenfromEthereumToCosmosAndBack tests the ICS20 transfer functionality
// by transferring ERC20 tokens from Ethereum to Cosmos chain
// and then back from Cosmos chain to Ethereum
func (s *EthereumCosmosIBCTestSuite) TestICS20TransferERC20TokenFromEthereumToCosmosAndBack() {
	ctx := context.Background()

	s.SetupSuite(ctx)

	eth, simd := s.ChainA, s.ChainB

	ics20Address := ethcommon.HexToAddress(s.contractAddresses.Ics20Transfer)
	transferAmount := big.NewInt(testvalues.TransferAmount)
	ethereumUserAddress := crypto.PubkeyToAddress(s.key.PublicKey)
	cosmosUserWallet := s.UserB
	cosmosUserAddress := cosmosUserWallet.FormattedAddress()

	s.Run("Approve the ICS20Transfer.sol contract to spend the erc20 tokens", func() {
		tx, err := s.erc20Contract.Approve(s.GetTransactOpts(s.key), ics20Address, transferAmount)
		s.Require().NoError(err)
		receipt := s.GetTxReceipt(ctx, eth, tx.Hash())
		s.Require().Equal(ethtypes.ReceiptStatusSuccessful, receipt.Status)

		allowance, err := s.erc20Contract.Allowance(nil, crypto.PubkeyToAddress(s.key.PublicKey), ics20Address)
		s.Require().NoError(err)
		s.Require().Equal(transferAmount, allowance)
	})

	var sendPacket ics26router.IICS26RouterMsgsPacket
	s.Run("sendTransfer to Ethereum", func() {
		timeout := uint64(time.Now().Add(30 * time.Minute).Unix())
		msgSendTransfer := ics20transfer.IICS20TransferMsgsSendTransferMsg{
			Denom:            s.contractAddresses.Erc20,
			Amount:           transferAmount,
			Receiver:         cosmosUserAddress,
			SourceChannel:    s.ethClientID,
			DestPort:         transfertypes.PortID,
			TimeoutTimestamp: timeout,
			Memo:             "",
		}

		tx, err := s.ics20Contract.SendTransfer(s.GetTransactOpts(s.key), msgSendTransfer)
		s.Require().NoError(err)
		receipt := s.GetTxReceipt(ctx, eth, tx.Hash())
		s.Require().Equal(ethtypes.ReceiptStatusSuccessful, receipt.Status)

		transferEvent, err := e2esuite.GetEvmEvent(receipt, s.ics20Contract.ParseICS20Transfer)
		s.Require().NoError(err)
		s.Require().Equal(s.contractAddresses.Erc20, strings.ToLower(transferEvent.Erc20Address.Hex()))
		s.Require().Equal(transferAmount, transferEvent.PacketData.Amount)
		s.Require().Equal(strings.ToLower(ethereumUserAddress.Hex()), strings.ToLower(transferEvent.PacketData.Sender))
		s.Require().Equal(cosmosUserAddress, transferEvent.PacketData.Receiver)
		s.Require().Equal("", transferEvent.PacketData.Memo)

		sendPacketEvent, err := e2esuite.GetEvmEvent(receipt, s.ics26Contract.ParseSendPacket)
		s.Require().NoError(err)
		sendPacket = sendPacketEvent.Packet
		s.Require().Equal(uint32(1), sendPacket.Sequence)
		s.Require().Equal(timeout, sendPacket.TimeoutTimestamp)
		s.Require().Equal(transfertypes.PortID, sendPacket.SourcePort)
		s.Require().Equal(s.ethClientID, sendPacket.SourceChannel)
		s.Require().Equal(transfertypes.PortID, sendPacket.DestPort)
		s.Require().Equal(s.simdClientID, sendPacket.DestChannel)
		s.Require().Equal(transfertypes.Version, sendPacket.Version)

		s.Run("Vrify balances on Ethereum", func() {
			userBalance, err := s.erc20Contract.BalanceOf(nil, ethereumUserAddress)
			s.Require().NoError(err)
			s.Require().Equal(testvalues.InitialBalance-testvalues.TransferAmount, userBalance.Int64())

			escrowBalance, err := s.erc20Contract.BalanceOf(nil, s.escrowContractAddr)
			s.Require().NoError(err)
			s.Require().Equal(testvalues.TransferAmount, escrowBalance.Int64())
		})
	})

	var recvAck []byte
	var denomOnCosmos transfertypes.DenomTrace
	s.Run("recvPacket on Cosmos chain", func() {
		tx, err := s.BroadcastMessages(ctx, simd, cosmosUserWallet, 200_000, &channeltypes.MsgRecvPacket{
			Packet: channeltypes.Packet{
				Sequence:           uint64(sendPacket.Sequence),
				SourcePort:         sendPacket.SourcePort,
				SourceChannel:      sendPacket.SourceChannel,
				DestinationPort:    sendPacket.DestPort,
				DestinationChannel: sendPacket.DestChannel,
				Data:               sendPacket.Data,
				TimeoutHeight:      clienttypes.Height{},
				TimeoutTimestamp:   sendPacket.TimeoutTimestamp * 1_000_000_000,
			},
			ProofCommitment: []byte("doesn't matter"),
			ProofHeight:     clienttypes.Height{},
			Signer:          cosmosUserAddress,
		})
		s.Require().NoError(err)

		recvAck, err = ibctesting.ParseAckFromEvents(tx.Events)
		s.Require().NoError(err)
		s.Require().NotNil(recvAck)

		s.Run("Verify balances on Cosmos chain", func() {
			denomOnCosmos = transfertypes.ParseDenomTrace(
				fmt.Sprintf("%s/%s/%s", transfertypes.PortID, "00-mock-0", s.contractAddresses.Erc20),
			)

			res, err := e2esuite.GRPCQuery[banktypes.QueryBalanceResponse](ctx, simd, &banktypes.QueryBalanceRequest{
				Address: cosmosUserAddress,
				Denom:   denomOnCosmos.IBCDenom(),
			})
			s.Require().NoError(err)
			s.Require().NotNil(res.Balance)
			s.Require().Equal(sdkmath.NewIntFromBigInt(transferAmount), res.Balance.Amount)
			s.Require().Equal(denomOnCosmos.IBCDenom(), res.Balance.Denom)
		})
	})

	s.Run("acknowledgePacket on Ethereum", func() {
		clientState, err := s.sp1Ics07Contract.GetClientState(nil)
		s.Require().NoError(err)

		trustedHeight := clientState.LatestHeight.RevisionHeight
		latestHeight, err := simd.Height(ctx)
		s.Require().NoError(err)

		packetAckPath := ibchost.PacketAcknowledgementPath(sendPacket.DestPort, sendPacket.DestChannel, uint64(sendPacket.Sequence))
		operator.UpdateClientAndMembershipProof(
			uint64(trustedHeight), uint64(latestHeight), packetAckPath,
			"--trust-level", testvalues.DefaultTrustLevel.String(),
			"--trusting-period", strconv.Itoa(testvalues.DefaultTrustPeriod),
		)

		tx, err := s.ics26Contract.AckPacket(s.GetTransactOpts(s.key), ics26router.IICS26RouterMsgsMsgAckPacket{
			Packet:          sendPacket,
			Acknowledgement: recvAck,
			ProofAcked:      []byte{},
			ProofHeight:     ics26router.IICS02ClientMsgsHeight{},
		})
		s.Require().NoError(err)

		receipt := s.GetTxReceipt(ctx, eth, tx.Hash())
		s.Require().Equal(ethtypes.ReceiptStatusSuccessful, receipt.Status)

		s.Run("Verify balances on Ethereum", func() {
			userBalance, err := s.erc20Contract.BalanceOf(nil, ethereumUserAddress)
			s.Require().NoError(err)
			s.Require().Equal(testvalues.InitialBalance-testvalues.TransferAmount, userBalance.Int64())

			escrowBalance, err := s.erc20Contract.BalanceOf(nil, s.escrowContractAddr)
			s.Require().NoError(err)
			s.Require().Equal(testvalues.TransferAmount, escrowBalance.Int64())
		})
	})

	var returnPacket channeltypes.Packet
	s.Run("Transfer tokens back from Cosmos chain", func() {
		timeout := uint64(time.Now().Add(30*time.Minute).Unix() * 1_000_000_000)
		ibcCoin := sdk.NewCoin(denomOnCosmos.IBCDenom(), sdkmath.NewIntFromBigInt(transferAmount))

		msg := transfertypes.MsgTransfer{
			SourcePort:       transfertypes.PortID,
			SourceChannel:    s.simdClientID,
			Token:            ibcCoin,
			Sender:           cosmosUserAddress,
			Receiver:         strings.ToLower(ethereumUserAddress.Hex()),
			TimeoutHeight:    clienttypes.Height{},
			TimeoutTimestamp: timeout,
			Memo:             "",
			DestPort:         transfertypes.PortID,
			DestChannel:      s.ethClientID,
		}

		tx, err := s.BroadcastMessages(ctx, simd, cosmosUserWallet, 200_000, &msg)
		s.Require().NoError(err)
		returnPacket, err = ibctesting.ParsePacketFromEvents(tx.Events)
		s.Require().NoError(err)

		s.Require().Equal(uint64(1), returnPacket.Sequence)
		s.Require().Equal(transfertypes.PortID, returnPacket.SourcePort)
		s.Require().Equal(s.simdClientID, returnPacket.SourceChannel)
		s.Require().Equal(transfertypes.PortID, returnPacket.DestinationPort)
		s.Require().Equal(s.ethClientID, returnPacket.DestinationChannel)
		s.Require().Equal(clienttypes.Height{}, returnPacket.TimeoutHeight)
		s.Require().Equal(timeout, returnPacket.TimeoutTimestamp)

		var transferPacketData transfertypes.FungibleTokenPacketData
		err = json.Unmarshal(returnPacket.Data, &transferPacketData)
		s.Require().NoError(err)
		s.Require().Equal(denomOnCosmos.GetFullDenomPath(), transferPacketData.Denom)
		s.Require().Equal(transferAmount.String(), transferPacketData.Amount)
		s.Require().Equal(cosmosUserAddress, transferPacketData.Sender)
		s.Require().Equal(strings.ToLower(ethereumUserAddress.Hex()), transferPacketData.Receiver)
		s.Require().Equal("", transferPacketData.Memo)

		s.Require().True(s.Run("Verify balances on Cosmos chain", func() {
			// User balance on Cosmos chain
			resp, err := e2esuite.GRPCQuery[banktypes.QueryBalanceResponse](ctx, simd, &banktypes.QueryBalanceRequest{
				Address: cosmosUserAddress,
				Denom:   denomOnCosmos.IBCDenom(),
			})
			s.Require().NoError(err)
			s.Require().NotNil(resp.Balance)
			s.Require().Equal(sdkmath.ZeroInt(), resp.Balance.Amount)
			s.Require().Equal(denomOnCosmos.GetFullDenomPath(), resp.Balance.Denom)
		}))
	})

	var returnWriteAckEvent *ics26router.ContractWriteAcknowledgement
	s.Run("Receive packet on Etherem", func() {
		clientState, err := s.sp1Ics07Contract.GetClientState(nil)
		s.Require().NoError(err)

		trustedHeight := clientState.LatestHeight.RevisionHeight
		latestHeight, err := simd.Height(ctx)
		s.Require().NoError(err)

		packetCommitmentPath := ibchost.PacketCommitmentPath(returnPacket.SourcePort, returnPacket.SourceChannel, returnPacket.Sequence)
		proofHeight, ucAndMemProof, err := operator.UpdateClientAndMembershipProof(
			uint64(trustedHeight), uint64(latestHeight), packetCommitmentPath,
			"--trust-level", testvalues.DefaultTrustLevel.String(),
			"--trusting-period", strconv.Itoa(testvalues.DefaultTrustPeriod),
		)
		s.Require().NoError(err)

		packet := ics26router.IICS26RouterMsgsPacket{
			Sequence:         uint32(returnPacket.Sequence),
			TimeoutTimestamp: returnPacket.TimeoutTimestamp / 1_000_000_000,
			SourcePort:       returnPacket.SourcePort,
			SourceChannel:    returnPacket.SourceChannel,
			DestPort:         returnPacket.DestinationPort,
			DestChannel:      returnPacket.DestinationChannel,
			Version:          transfertypes.Version,
			Data:             returnPacket.Data,
		}
		msg := ics26router.IICS26RouterMsgsMsgRecvPacket{
			Packet:          packet,
			ProofCommitment: ucAndMemProof,
			ProofHeight:     *proofHeight,
		}

		tx, err := s.ics26Contract.RecvPacket(s.GetTransactOpts(s.key), msg)
		s.Require().NoError(err)

		receipt := s.GetTxReceipt(ctx, eth, tx.Hash())
		s.Require().Equal(ethtypes.ReceiptStatusSuccessful, receipt.Status)

		returnWriteAckEvent, err = e2esuite.GetEvmEvent(receipt, s.ics26Contract.ParseWriteAcknowledgement)
		s.Require().NoError(err)

		receiveEvent, err := e2esuite.GetEvmEvent(receipt, s.ics20Contract.ParseICS20ReceiveTransfer)
		s.Require().NoError(err)
		ethReceiveData := receiveEvent.PacketData
		s.Require().Equal(denomOnCosmos.GetFullDenomPath(), ethReceiveData.Denom)
		s.Require().Equal(s.contractAddresses.Erc20, strings.ToLower(receiveEvent.Erc20Address.Hex()))
		s.Require().Equal(cosmosUserAddress, ethReceiveData.Sender)
		s.Require().Equal(strings.ToLower(ethereumUserAddress.Hex()), ethReceiveData.Receiver)
		s.Require().Equal(transferAmount, ethReceiveData.Amount) // the amount transferred the user on the evm side is converted, but the packet doesn't change
		s.Require().Equal("", ethReceiveData.Memo)

		s.True(s.Run("Verify balances on Ethereum", func() {
			// User balance should be back to the starting point
			userBalance, err := s.erc20Contract.BalanceOf(nil, ethereumUserAddress)
			s.Require().NoError(err)
			s.Require().Equal(testvalues.InitialBalance, userBalance.Int64())

			escrowBalance, err := s.erc20Contract.BalanceOf(nil, s.escrowContractAddr)
			s.Require().NoError(err)
			s.Require().Equal(int64(0), escrowBalance.Int64())
		}))
	})

	s.Require().True(s.Run("Acknowledge packet on Cosmos chain", func() {
		resp, err := e2esuite.GRPCQuery[clienttypes.QueryClientStateResponse](ctx, simd, &clienttypes.QueryClientStateRequest{
			ClientId: s.simdClientID,
		})
		s.Require().NoError(err)
		var clientState mock.ClientState
		err = simd.Config().EncodingConfig.Codec.Unmarshal(resp.ClientState.Value, &clientState)
		s.Require().NoError(err)

		txResp, err := s.BroadcastMessages(ctx, simd, cosmosUserWallet, 200_000, &channeltypes.MsgAcknowledgement{
			Packet:          returnPacket,
			Acknowledgement: returnWriteAckEvent.Acknowledgement,
			ProofAcked:      []byte("doesn't matter"), // Because mock light client
			ProofHeight:     clienttypes.Height{},
			Signer:          cosmosUserAddress,
		})
		s.Require().NoError(err)
		s.Require().Equal(uint32(0), txResp.Code)
	}))
}
