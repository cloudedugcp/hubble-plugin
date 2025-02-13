package main

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/your-username/your-repo/pkg/hubble" // Імпортуємо пакет з pkg
)

const (
	PluginID          uint32 = 6
	PluginName               = "hubble"
	PluginDescription        = "Hubble Events"
	PluginContact            = "github.com/falcosecurity/plugins/"
	PluginVersion            = "0.1.0"
	PluginEventSource        = "hubble"
)

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &hubble.Plugin{}
		p.SetInfo(
			PluginID,
			PluginName,
			PluginDescription,
			PluginContact,
			PluginVersion,
			PluginEventSource,
		)
		extractor.Register(p)
		source.Register(p)
		return p
	})
}

func main() {}
