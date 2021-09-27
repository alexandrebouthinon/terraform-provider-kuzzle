package main

import (
	"github.com/alexandrebouthinon/terraform-provider-kuzzle/kuzzle"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: kuzzle.Provider,
	})
}
