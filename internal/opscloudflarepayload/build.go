package opscloudflarepayload

import (
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const BundleOutputDirectory = ".agentops-production-bundle"

var wrangler4107VersionPattern = regexp.MustCompile(`^4\.107\.[0-9]+$`)

var ErrUnsupportedWranglerProfile = errors.New("Cloudflare Wrangler version is unsupported by the API profile")

func ValidateWranglerVersion(profile, version string) error {
	if profile != supportedProfile || !wrangler4107VersionPattern.MatchString(version) {
		return ErrUnsupportedWranglerProfile
	}
	return nil
}

func BuildPayload(root, configPath, bundleDirectory, profile string) (Payload, CanonicalConfig, error) {
	if root == "" || !validRelativePayloadPath(configPath) || !validRelativePayloadPath(bundleDirectory) {
		return Payload{}, CanonicalConfig{}, errors.New("Cloudflare payload configuration path is invalid")
	}
	configuration, err := Capture(root, []string{configPath})
	if err != nil {
		return Payload{}, CanonicalConfig{}, err
	}
	configurationBytes, ok := configuration.File(configPath)
	if !ok {
		return Payload{}, CanonicalConfig{}, errors.New("Cloudflare payload configuration is unavailable")
	}
	config, err := ParseWranglerConfig(profile, configurationBytes)
	if err != nil {
		return Payload{}, CanonicalConfig{}, err
	}
	_, mainName, bundledModules, err := findBundledModules(root, bundleDirectory)
	if err != nil {
		return Payload{}, CanonicalConfig{}, err
	}
	config.Main = mainName

	paths := make([]string, 0, len(bundledModules))
	for _, module := range bundledModules {
		paths = append(paths, module.path)
	}
	base := filepath.Dir(configPath)
	assetNames := make([]string, 0)
	assetDirectory := ""
	if config.Assets != nil {
		assetDirectory = filepath.Clean(filepath.Join(base, config.Assets.Directory))
		if config.Assets.Directory == "" || filepath.IsAbs(config.Assets.Directory) || !validRelativePayloadPath(assetDirectory) {
			return Payload{}, CanonicalConfig{}, errors.New("Cloudflare payload asset directory is invalid")
		}
		assetRoot := filepath.Join(root, assetDirectory)
		err = filepath.WalkDir(assetRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return errors.New("Cloudflare payload asset path is unavailable")
			}
			if entry.Type()&fs.ModeSymlink != 0 {
				return errors.New("Cloudflare payload asset symlink is unsupported")
			}
			if entry.IsDir() {
				return nil
			}
			if !entry.Type().IsRegular() {
				return errors.New("Cloudflare payload asset must be a regular file")
			}
			relative, relativeErr := filepath.Rel(root, path)
			if relativeErr != nil || !validRelativePayloadPath(relative) {
				return errors.New("Cloudflare payload asset path is invalid")
			}
			name, nameErr := filepath.Rel(assetRoot, path)
			if nameErr != nil || !validRelativePayloadPath(name) {
				return errors.New("Cloudflare payload asset name is invalid")
			}
			paths = append(paths, relative)
			assetNames = append(assetNames, filepath.ToSlash(name))
			return nil
		})
		if err != nil {
			return Payload{}, CanonicalConfig{}, err
		}
	}

	captured, err := Capture(root, paths)
	if err != nil {
		return Payload{}, CanonicalConfig{}, err
	}
	modules := make([]Module, 0, len(bundledModules))
	for _, bundled := range bundledModules {
		content, found := captured.File(bundled.path)
		if !found {
			return Payload{}, CanonicalConfig{}, errors.New("Cloudflare payload module is unavailable")
		}
		modules = append(modules, Module{Name: bundled.name, Type: bundled.contentType, Bytes: content})
	}
	assets := make([]Asset, 0, len(assetNames))
	if config.Assets != nil {
		sort.Strings(assetNames)
		for _, name := range assetNames {
			content, found := captured.File(filepath.Join(assetDirectory, filepath.FromSlash(name)))
			if !found {
				return Payload{}, CanonicalConfig{}, errors.New("Cloudflare payload asset is unavailable")
			}
			assets = append(assets, Asset{Path: name, Bytes: content})
		}
	}
	metadata, err := config.Metadata()
	if err != nil {
		return Payload{}, CanonicalConfig{}, err
	}
	payload, err := NewPayload(mainName, modules, assets, metadata)
	if err != nil {
		return Payload{}, CanonicalConfig{}, err
	}
	return payload, config, nil
}

type bundledModule struct {
	path        string
	name        string
	contentType string
}

func findBundledModules(root, bundleDirectory string) (string, string, []bundledModule, error) {
	bundleRoot := filepath.Join(root, bundleDirectory)
	var candidates []bundledModule
	var ignored []string
	err := filepath.WalkDir(bundleRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("Cloudflare Wrangler bundle is unavailable")
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return errors.New("Cloudflare Wrangler bundle symlink is unsupported")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("Cloudflare Wrangler bundle must contain regular files")
		}
		relative, relativeErr := filepath.Rel(root, path)
		if relativeErr != nil || !validRelativePayloadPath(relative) {
			return errors.New("Cloudflare Wrangler bundle path is invalid")
		}
		name, nameErr := filepath.Rel(bundleRoot, path)
		if nameErr != nil || !validRelativePayloadPath(name) {
			return errors.New("Cloudflare Wrangler bundle module name is invalid")
		}
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		switch extension {
		case ".js", ".mjs":
			candidates = append(candidates, bundledModule{path: relative, name: filepath.ToSlash(name), contentType: "application/javascript+module"})
		case ".wasm":
			candidates = append(candidates, bundledModule{path: relative, name: filepath.ToSlash(name), contentType: "application/wasm"})
		case ".md", ".map":
			ignored = append(ignored, filepath.ToSlash(name))
		default:
			return errors.New("Cloudflare Wrangler bundle contains an unsupported output")
		}
		return nil
	})
	if err != nil {
		return "", "", nil, err
	}
	var mainCandidates []bundledModule
	for _, candidate := range candidates {
		if candidate.contentType == "application/javascript+module" {
			mainCandidates = append(mainCandidates, candidate)
		}
	}
	if len(mainCandidates) != 1 {
		return "", "", nil, errors.New("Cloudflare Wrangler bundle must contain exactly one JavaScript module")
	}
	main := mainCandidates[0]
	for _, name := range ignored {
		if name != "README.md" && name != main.name+".map" {
			return "", "", nil, errors.New("Cloudflare Wrangler bundle contains unsupported metadata")
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })
	return main.path, main.name, candidates, nil
}

func validRelativePayloadPath(value string) bool {
	clean := filepath.Clean(value)
	return value != "" && !filepath.IsAbs(value) && clean == value && clean != "." && clean != ".." &&
		!strings.HasPrefix(clean, ".."+string(filepath.Separator)) && !strings.ContainsAny(value, "\x00\r\n")
}
