package opscloudflarepayload

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

const supportedProfile = "wrangler-4.107-preveal-v1"

type Module struct {
	Name  string
	Type  string
	Bytes []byte
}

type Asset struct {
	Path  string
	Bytes []byte
}

type Payload struct {
	MainModule string
	Modules    []Module
	Assets     []Asset
	Metadata   []byte
	SHA256     string

	files map[string][]byte
}

func NewPayload(mainModule string, modules []Module, assets []Asset, metadata []byte) (Payload, error) {
	if mainModule == "" || len(modules) == 0 || len(metadata) == 0 {
		return Payload{}, errors.New("Cloudflare payload is incomplete")
	}
	if err := validateCanonicalMetadata(metadata); err != nil {
		return Payload{}, err
	}
	payload := Payload{
		MainModule: mainModule,
		Modules:    cloneModules(modules),
		Assets:     cloneAssets(assets),
		Metadata:   append([]byte(nil), metadata...),
	}
	if err := validateModules(payload.MainModule, payload.Modules); err != nil {
		return Payload{}, err
	}
	payload.SHA256 = digestPayload(payload)
	return payload, nil
}

func validateModules(mainModule string, modules []Module) error {
	foundMain := false
	seen := make(map[string]bool, len(modules))
	for _, module := range modules {
		if module.Name == "" || len(module.Bytes) == 0 || module.Type != "application/javascript+module" || seen[module.Name] {
			return errors.New("Cloudflare payload module is unsupported")
		}
		seen[module.Name] = true
		foundMain = foundMain || module.Name == mainModule
	}
	if !foundMain {
		return errors.New("Cloudflare payload main module is missing")
	}
	return nil
}

func digestPayload(payload Payload) string {
	hash := sha256.New()
	fmt.Fprintf(hash, "main\x00%s\x00metadata\x00%d\x00", payload.MainModule, len(payload.Metadata))
	_, _ = hash.Write(payload.Metadata)
	_, _ = hash.Write([]byte{0})
	modules := cloneModules(payload.Modules)
	sort.Slice(modules, func(i, j int) bool { return modules[i].Name < modules[j].Name })
	for _, module := range modules {
		fmt.Fprintf(hash, "module\x00%s\x00%s\x00%d\x00", module.Name, module.Type, len(module.Bytes))
		_, _ = hash.Write(module.Bytes)
		_, _ = hash.Write([]byte{0})
	}
	assets := cloneAssets(payload.Assets)
	sort.Slice(assets, func(i, j int) bool { return assets[i].Path < assets[j].Path })
	for _, asset := range assets {
		fmt.Fprintf(hash, "asset\x00%s\x00%d\x00", asset.Path, len(asset.Bytes))
		_, _ = hash.Write(asset.Bytes)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// CanonicalDigest returns the digest only when it still represents every owned
// metadata, module, and asset byte in the payload.
func CanonicalDigest(payload Payload) (string, error) {
	digest := digestPayload(payload)
	if payload.SHA256 == "" || payload.SHA256 != digest {
		return "", errors.New("Cloudflare payload digest is stale")
	}
	return digest, nil
}

func cloneModules(input []Module) []Module {
	output := make([]Module, len(input))
	for index, module := range input {
		output[index] = module
		output[index].Bytes = append([]byte(nil), module.Bytes...)
	}
	return output
}

func cloneAssets(input []Asset) []Asset {
	output := make([]Asset, len(input))
	for index, asset := range input {
		output[index] = asset
		output[index].Bytes = append([]byte(nil), asset.Bytes...)
	}
	return output
}
