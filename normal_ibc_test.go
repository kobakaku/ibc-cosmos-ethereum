package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	transfertypes "github.com/cosmos/ibc-go/v8/modules/apps/transfer/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"

	"cosmossdk.io/math"
	"github.com/strangelove-ventures/interchaintest/v8"
	"github.com/strangelove-ventures/interchaintest/v8/chain/cosmos"
	"github.com/strangelove-ventures/interchaintest/v8/ibc"
	"github.com/strangelove-ventures/interchaintest/v8/testreporter"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestNormalIBC(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Chain Factory
	cf := interchaintest.NewBuiltinChainFactory(zaptest.NewLogger(t), []*interchaintest.ChainSpec{
		{Name: "gaia", Version: "v7.0.0", ChainConfig: ibc.ChainConfig{
			GasPrices: "0.0uatom",
		}},
		{Name: "osmosis", Version: "v11.0.0"},
	})

	chains, err := cf.Chains(t.Name())
	require.NoError(t, err)
	gaia, osmosis := chains[0].(*cosmos.CosmosChain), chains[1].(*cosmos.CosmosChain)

	// Relayer Factory
	client, network := interchaintest.DockerSetup(t)
	r := interchaintest.NewBuiltinRelayerFactory(ibc.CosmosRly, zaptest.NewLogger(t)).Build(
		t, client, network)

	// Prep Interchain
	const ibcPath = "gaia-osmo-demo"
	ic := interchaintest.NewInterchain().
		AddChain(gaia).
		AddChain(osmosis).
		AddRelayer(r, "relayer").
		AddLink(interchaintest.InterchainLink{
			Chain1:  gaia,
			Chain2:  osmosis,
			Relayer: r,
			Path:    ibcPath,
		})

	// Log location
	f, err := interchaintest.CreateLogFile(fmt.Sprintf("%d.json", time.Now().Unix()))
	require.NoError(t, err)
	// Reporter/logs
	rep := testreporter.NewReporter(f)
	eRep := rep.RelayerExecReporter(t)

	// Build interchain
	require.NoError(t, ic.Build(ctx, eRep, interchaintest.InterchainBuildOptions{
		TestName:  t.Name(),
		Client:    client,
		NetworkID: network,
		// BlockDatabaseFile: interchaintest.DefaultBlockDatabaseFilepath(),

		SkipPathCreation: false,
	},
	),
	)

	// Create and fund user wallets
	fundAmount := math.NewInt(10_000_000)
	users := interchaintest.GetAndFundTestUsers(t, ctx, t.Name(), fundAmount, gaia, osmosis)
	gaiaUser := users[0]
	osmosisUser := users[1]

	gaiaUserInitialBal, err := gaia.GetBalance(ctx, gaiaUser.FormattedAddress(), gaia.Config().Denom)
	fmt.Printf("%+v\n", gaia.Config())
	require.NoError(t, err)
	require.True(t, gaiaUserInitialBal.Equal(fundAmount))

	// Get channel id
	gaiaChannelInfo, err := r.GetChannels(ctx, eRep, gaia.Config().ChainID)
	require.NoError(t, err)
	gaiaChannelId := gaiaChannelInfo[0].ChannelID

	osmoChannelInfo, err := r.GetChannels(ctx, eRep, osmosis.Config().ChainID)
	require.NoError(t, err)
	osmoChannelId := osmoChannelInfo[0].ChannelID

	height, err := osmosis.Height(ctx)
	require.NoError(t, err)

	// Send transaction
	amountToSend := math.NewInt(1_000_000)
	dstAddress := osmosisUser.FormattedAddress()
	transfer := ibc.WalletAmount{
		Address: dstAddress,
		Denom:   gaia.Config().Denom,
		Amount:  amountToSend,
	}
	tx, err := gaia.SendIBCTransfer(ctx, gaiaChannelId, gaiaUser.KeyName(), transfer, ibc.TransferOptions{})
	require.NoError(t, err)
	require.NoError(t, tx.Validate())

	// Relay MsgRecvpacket to osmosis, then MsgAcknowledgement back to gaia
	require.NoError(t, r.Flush(ctx, eRep, ibcPath, gaiaChannelId))

	// Test source wallet has decreased funds
	expectedBal := gaiaUserInitialBal.Sub(amountToSend)
	gaiaUserNewBal, err := gaia.GetBalance(ctx, gaiaUser.FormattedAddress(), gaia.Config().Denom)
	require.NoError(t, err)
	require.True(t, gaiaUserNewBal.Equal(expectedBal))

	// Trace IBC denom
	srcDenomTrace := transfertypes.ParseDenomTrace(transfertypes.GetPrefixedDenom("transfer", osmoChannelId, gaia.Config().Denom))
	dstIbcDenom := srcDenomTrace.IBCDenom()

	// Test destination wallet has increased funds
	osmosUserNewBal, err := osmosis.GetBalance(ctx, osmosisUser.FormattedAddress(), dstIbcDenom)
	require.NoError(t, err)
	require.True(t, osmosUserNewBal.Equal(amountToSend))

	// Validate light client
	reg := osmosis.Config().EncodingConfig.InterfaceRegistry
	msg, err := cosmos.PollForMessage[*clienttypes.MsgUpdateClient](ctx, osmosis, reg, height, height+10, nil)
	require.NoError(t, err)

	require.Equal(t, "07-tendermint-0", msg.ClientId)
	require.NotEmpty(t, msg, msg.Signer)
}
