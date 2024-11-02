package e2esuite

import (
	"context"

	"ibc-cosmos-ethereum-test/e2e/interchaintestv8/chainconfig"

	sdkmath "cosmossdk.io/math"
	dockerclient "github.com/docker/docker/client"

	"github.com/strangelove-ventures/interchaintest/v8"
	"github.com/strangelove-ventures/interchaintest/v8/chain/cosmos"
	"github.com/strangelove-ventures/interchaintest/v8/chain/ethereum"
	"github.com/strangelove-ventures/interchaintest/v8/ibc"
	"github.com/strangelove-ventures/interchaintest/v8/testreporter"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap/zaptest"
)

type TestSuite struct {
	suite.Suite

	ChainA       *ethereum.EthereumChain
	ChainB       *cosmos.CosmosChain
	UserA        ibc.Wallet
	UserB        ibc.Wallet
	dockerclient *dockerclient.Client
	network      string
}

func (s *TestSuite) SetupSuite(ctx context.Context) {
	t := s.T()

	// Chain Factory
	cf := interchaintest.NewBuiltinChainFactory(zaptest.NewLogger(t), chainconfig.DefaultChainSpecs)

	chains, err := cf.Chains(t.Name())
	s.Require().NoError(err)
	s.ChainA, s.ChainB = chains[0].(*ethereum.EthereumChain), chains[1].(*cosmos.CosmosChain)

	// Prep Interchain
	ic := interchaintest.NewInterchain().
		AddChain(s.ChainA).
		AddChain(s.ChainB)

	// Reporter/logs
	eRep := testreporter.NewNopReporter().RelayerExecReporter(t)

	// Build interchain
	s.dockerclient, s.network = interchaintest.DockerSetup(t)
	require.NoError(t, ic.Build(ctx, eRep, interchaintest.InterchainBuildOptions{
		TestName:         t.Name(),
		Client:           s.dockerclient,
		NetworkID:        s.network,
		SkipPathCreation: true,
	},
	),
	)

	// map all query request types to their gRPC method paths for cosmos chains
	s.Require().NoError(populateQueryReqToPath(ctx, s.ChainB))

	// Fund user accounts
	ethFundAmount := sdkmath.NewInt(2 * ethereum.ETHER)
	s.UserA = interchaintest.GetAndFundTestUsers(t, ctx, t.Name(), ethFundAmount, s.ChainA)[0]
	cosmosFundAmount := sdkmath.NewInt(1_000_000_000_000)
	s.UserB = interchaintest.GetAndFundTestUsers(t, ctx, t.Name(), cosmosFundAmount, s.ChainB)[0]
}
