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
	mainPath, mainName, err := findBundledMain(root, bundleDirectory)
	if err != nil {
		return Payload{}, CanonicalConfig{}, err
	}
	config.Main = mainName

	paths := []string{mainPath}
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
	mainBytes, ok := captured.File(mainPath)
	if !ok {
		return Payload{}, CanonicalConfig{}, errors.New("Cloudflare payload main module is unavailable")
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
	payload, err := NewPayload(mainName, []Module{{Name: mainName, Type: "application/javascript+module", Bytes: mainBytes}}, assets, metadata)
	if err != nil {
		return Payload{}, CanonicalConfig{}, err
	}
	return payload, config, nil
}

func findBundledMain(root, bundleDirectory string) (string, string, error) {
	bundleRoot := filepath.Join(root, bundleDirectory)
	var candidates []string
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
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if extension != ".js" && extension != ".mjs" {
			return errors.New("Cloudflare Wrangler bundle contains an unsupported output")
		}
		relative, relativeErr := filepath.Rel(root, path)
		if relativeErr != nil || !validRelativePayloadPath(relative) {
			return errors.New("Cloudflare Wrangler bundle path is invalid")
		}
		candidates = append(candidates, relative)
		return nil
	})
	if err != nil {
		return "", "", err
	}
	if len(candidates) != 1 {
		return "", "", errors.New("Cloudflare Wrangler bundle must contain exactly one JavaScript module")
	}
	name, err := filepath.Rel(bundleDirectory, candidates[0])
	if err != nil || !validRelativePayloadPath(name) {
		return "", "", errors.New("Cloudflare Wrangler bundle module name is invalid")
	}
	return candidates[0], filepath.ToSlash(name), nil
}

func validRelativePayloadPath(value string) bool {
	clean := filepath.Clean(value)
	return value != "" && !filepath.IsAbs(value) && clean == value && clean != "." && clean != ".." &&
		!strings.HasPrefix(clean, ".."+string(filepath.Separator)) && !strings.ContainsAny(value, "\x00\r\n")
}
