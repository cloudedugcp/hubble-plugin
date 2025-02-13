package hubble

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"github.com/alecthomas/jsonschema"

	"github.com/cilium/cilium/api/v1/observer"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"google.golang.org/grpc"
)

var (
	ID          uint32
	Name        string
	Description string
	Contact     string
	Version     string
	EventSource string
)

// PluginConfig містить конфігурацію плагіну
type PluginConfig struct {
	HubbleAddress string `json:"hubbleAddress" jsonschema:"description=Address of Hubble API (Default: localhost:4245)"`
}

// Plugin представляє основний плагін Hubble
type Plugin struct {
	plugins.BasePlugin
	Config PluginConfig
}

// SetDefault встановлює значення за замовчуванням для конфігурації
func (p *PluginConfig) setDefault() {
	p.HubbleAddress = "localhost:4245"
}

// SetInfo встановлює інформацію про плагін
func (p *Plugin) SetInfo(id uint32, name, description, contact, version, eventSource string) {
	ID = id
	Name = name
	Contact = contact
	Version = version
	EventSource = eventSource
}

// Info повертає інформацію про плагін
func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          ID,
		Name:        Name,
		Description: Description,
		Contact:     Contact,
		Version:     Version,
		EventSource: EventSource,
	}
}

// InitSchema повертає JSON-схему для конфігурації плагіну
func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

// Init ініціалізує плагін з конфігурацією
func (p *Plugin) Init(config string) error {
	p.Config.setDefault()
	return json.Unmarshal([]byte(config), &p.Config)
}



// Fields повертає список полів, які можна витягувати з подій Hubble
func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "hubble.event_type", Desc: "Type of the event"},
		{Type: "string", Name: "hubble.source_ip", Desc: "Source ip"},
		{Type: "string", Name: "hubble.destination_ip", Desc: "Destination ip"},
		{Type: "string", Name: "hubble.traffic_direction", Desc: "traffic_direction"},
		{Type: "string", Name: "hubble.flow_type", Desc: "flow type"},
		{Type: "string", Name: "hubble.pod_name", Desc: "pod name"},
		{Type: "string", Name: "hubble.verdict", Desc: "Verdict of the event"},
		{Type: "string", Name: "hubble.summary", Desc: "Summary of the event"},
	}
}

// Extract витягує значення поля з події Hubble
func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	var flow observer.GetFlowsResponse
	if err := json.NewDecoder(evt.Reader()).Decode(&flow); err != nil {
		return err
	}

	switch req.Field() {
	case "hubble.event_type":
		req.SetValue(flow.GetFlow().GetEventType().String())
	case "hubble.source_ip":
		req.SetValue(flow.GetFlow().GetIP().GetSource())
	case "hubble.destination_ip":
		req.SetValue(flow.GetFlow().GetIP().GetDestination())
	case "hubble.traffic_direction":
		req.SetValue(flow.GetFlow().GetTrafficDirection().String())
	case "hubble.flow_type":
		req.SetValue(flow.GetFlow().GetType().String())
	case "hubble.pod_name":
		req.SetValue(flow.GetFlow().GetDestination().GetPodName())
	case "hubble.verdict":
		req.SetValue(flow.GetFlow().GetVerdict().String())
	case "hubble.summary":
		req.SetValue(flow.GetFlow().GetSummary())
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}

// Open відкриває з'єднання з Hubble та повертає потік подій
func (p *Plugin) Open(params string) (source.Instance, error) {
	conn, err := grpc.Dial(p.Config.HubbleAddress, grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Hubble: %v", err)
	}

	client := observer.NewObserverClient(conn)
	request := &observer.GetFlowsRequest{Follow: true}
	stream, err := client.GetFlows(context.Background(), request)
	if err != nil {
		return nil, fmt.Errorf("failed to get flows: %v", err)
	}

	eventC := make(chan source.PushEvent)
	go func() {
		defer close(eventC)
		for {
			flow, err := stream.Recv()
			if err != nil {
				eventC <- source.PushEvent{Err: err}
				return
			}
			bytes, err := json.Marshal(flow)
			if err != nil {
				eventC <- source.PushEvent{Err: err}
				return
			}
			eventC <- source.PushEvent{Data: bytes}
		}
	}()

	instance, err := source.NewPushInstance(eventC)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

// String перетворює подію у рядок (необов'язково)
func (p *Plugin) String(in io.ReadSeeker) (string, error) {
	evtBytes, err := ioutil.ReadAll(in)
	if err != nil {
		return "", err
	}
	return string(evtBytes), nil
}
