package opscloudflarepayload

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/tailscale/hujson"
)

type CanonicalConfig struct {
	Profile            string            `json:"profile"`
	Name               string            `json:"name"`
	AccountID          string            `json:"account_id"`
	Main               string            `json:"main"`
	CompatibilityDate  string            `json:"compatibility_date"`
	CompatibilityFlags []string          `json:"compatibility_flags,omitempty"`
	WorkersDev         bool              `json:"workers_dev"`
	PreviewURLs        bool              `json:"preview_urls"`
	Assets             *AssetsConfig     `json:"assets,omitempty"`
	Routes             []RouteConfig     `json:"routes,omitempty"`
	Crons              []string          `json:"crons,omitempty"`
	KVNamespaces       []KVNamespace     `json:"kv_namespaces,omitempty"`
	D1Databases        []D1Database      `json:"d1_databases,omitempty"`
	R2Buckets          []R2Bucket        `json:"r2_buckets,omitempty"`
	AI                 *AIBinding        `json:"ai,omitempty"`
	Vectorize          []VectorizeIndex  `json:"vectorize,omitempty"`
	DurableObjects     []DurableObject   `json:"durable_objects,omitempty"`
	Migrations         []Migration       `json:"migrations,omitempty"`
	Vars               map[string]string `json:"vars,omitempty"`
}

type AssetsConfig struct {
	Directory        string `json:"-"`
	Binding          string `json:"binding,omitempty"`
	RunWorkerFirst   bool   `json:"run_worker_first,omitempty"`
	NotFoundHandling string `json:"not_found_handling,omitempty"`
}

type RouteConfig struct {
	Pattern      string `json:"pattern"`
	CustomDomain bool   `json:"custom_domain,omitempty"`
}

type KVNamespace struct {
	Binding string `json:"binding"`
	ID      string `json:"id"`
}

type D1Database struct {
	Binding       string `json:"binding"`
	DatabaseName  string `json:"database_name"`
	DatabaseID    string `json:"database_id"`
	MigrationsDir string `json:"migrations_dir,omitempty"`
}

type R2Bucket struct {
	Binding    string `json:"binding"`
	BucketName string `json:"bucket_name"`
}

type AIBinding struct {
	Binding string `json:"binding"`
}

type VectorizeIndex struct {
	Binding   string `json:"binding"`
	IndexName string `json:"index_name"`
}

type DurableObject struct {
	Name      string `json:"name"`
	ClassName string `json:"class_name"`
}

type Migration struct {
	Tag              string        `json:"tag"`
	NewSQLiteClasses []string      `json:"new_sqlite_classes,omitempty"`
	NewClasses       []string      `json:"new_classes,omitempty"`
	RenamedClasses   []ClassRename `json:"renamed_classes,omitempty"`
	DeletedClasses   []string      `json:"deleted_classes,omitempty"`
}

type ClassRename struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type wranglerConfig struct {
	Name               string            `json:"name"`
	AccountID          string            `json:"account_id"`
	Main               string            `json:"main"`
	CompatibilityDate  string            `json:"compatibility_date"`
	CompatibilityFlags []string          `json:"compatibility_flags"`
	WorkersDev         *bool             `json:"workers_dev"`
	PreviewURLs        *bool             `json:"preview_urls"`
	Assets             *assetsConfigWire `json:"assets"`
	Routes             []RouteConfig     `json:"routes"`
	Triggers           *triggerConfig    `json:"triggers"`
	KVNamespaces       []KVNamespace     `json:"kv_namespaces"`
	D1Databases        []D1Database      `json:"d1_databases"`
	R2Buckets          []R2Bucket        `json:"r2_buckets"`
	AI                 *AIBinding        `json:"ai"`
	Vectorize          []VectorizeIndex  `json:"vectorize"`
	DurableObjects     *durableObjects   `json:"durable_objects"`
	Migrations         []Migration       `json:"migrations"`
	Vars               map[string]string `json:"vars"`
}

type triggerConfig struct {
	Crons []string `json:"crons"`
}

type durableObjects struct {
	Bindings []DurableObject `json:"bindings"`
}

type assetsConfigWire struct {
	Directory        string `json:"directory"`
	Binding          string `json:"binding"`
	RunWorkerFirst   bool   `json:"run_worker_first"`
	NotFoundHandling string `json:"not_found_handling"`
}

func ParseWranglerConfig(profile string, input []byte) (CanonicalConfig, error) {
	if profile != supportedProfile || len(input) == 0 {
		return CanonicalConfig{}, errors.New("Cloudflare Wrangler profile is unsupported")
	}
	standard, err := hujson.Standardize(input)
	if err != nil {
		return CanonicalConfig{}, errors.New("Cloudflare Wrangler JSONC is invalid")
	}
	if err := rejectDuplicateJSONKeys(standard); err != nil {
		return CanonicalConfig{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(standard))
	decoder.DisallowUnknownFields()
	var raw wranglerConfig
	if err := decoder.Decode(&raw); err != nil {
		return CanonicalConfig{}, fmt.Errorf("Cloudflare Wrangler configuration is unsupported: %w", err)
	}
	if err := requireJSONEnd(decoder); err != nil {
		return CanonicalConfig{}, err
	}
	if raw.WorkersDev == nil || raw.PreviewURLs == nil {
		return CanonicalConfig{}, errors.New("Cloudflare Wrangler endpoint policy is incomplete")
	}
	config := CanonicalConfig{
		Profile: profile, Name: raw.Name, AccountID: raw.AccountID, Main: raw.Main,
		CompatibilityDate: raw.CompatibilityDate, CompatibilityFlags: append([]string(nil), raw.CompatibilityFlags...),
		WorkersDev: *raw.WorkersDev, PreviewURLs: *raw.PreviewURLs, Assets: canonicalAssets(raw.Assets),
		Routes: append([]RouteConfig(nil), raw.Routes...), KVNamespaces: append([]KVNamespace(nil), raw.KVNamespaces...),
		D1Databases: append([]D1Database(nil), raw.D1Databases...), R2Buckets: append([]R2Bucket(nil), raw.R2Buckets...),
		AI: cloneAI(raw.AI), Vectorize: append([]VectorizeIndex(nil), raw.Vectorize...), Migrations: cloneMigrations(raw.Migrations),
		Vars: cloneVars(raw.Vars),
	}
	if raw.Triggers != nil {
		config.Crons = append([]string(nil), raw.Triggers.Crons...)
	}
	if raw.DurableObjects != nil {
		config.DurableObjects = append([]DurableObject(nil), raw.DurableObjects.Bindings...)
	}
	if raw.Assets != nil && strings.TrimSpace(raw.Assets.Directory) == "" {
		return CanonicalConfig{}, errors.New("Cloudflare Wrangler assets source directory is incomplete")
	}
	if err := config.validate(); err != nil {
		return CanonicalConfig{}, err
	}
	return config, nil
}

func (c CanonicalConfig) Metadata() ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

func validateCanonicalMetadata(metadata []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(metadata))
	decoder.DisallowUnknownFields()
	var config CanonicalConfig
	if err := decoder.Decode(&config); err != nil {
		return errors.New("Cloudflare payload metadata is invalid")
	}
	if err := requireJSONEnd(decoder); err != nil {
		return err
	}
	if err := config.validate(); err != nil {
		return err
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, metadata) {
		return errors.New("Cloudflare payload metadata is not canonical")
	}
	return nil
}

func (c CanonicalConfig) validate() error {
	if c.Profile != supportedProfile || empty(c.Name, c.AccountID, c.Main, c.CompatibilityDate) {
		return errors.New("Cloudflare Wrangler identity or runtime is incomplete")
	}
	if c.WorkersDev || c.PreviewURLs {
		return errors.New("Cloudflare Wrangler public preview endpoints are unsupported")
	}
	seenFlags := make(map[string]bool, len(c.CompatibilityFlags))
	for _, flag := range c.CompatibilityFlags {
		if flag != "nodejs_compat" || seenFlags[flag] {
			return errors.New("Cloudflare Wrangler compatibility flag is unsupported")
		}
		seenFlags[flag] = true
	}
	if c.Assets != nil && (c.Assets.Binding == "" || c.Assets.NotFoundHandling == "") {
		return errors.New("Cloudflare Wrangler assets are incomplete")
	}
	for _, route := range c.Routes {
		if empty(route.Pattern) {
			return errors.New("Cloudflare Wrangler route is incomplete")
		}
	}
	for _, cron := range c.Crons {
		if strings.TrimSpace(cron) == "" {
			return errors.New("Cloudflare Wrangler schedule is incomplete")
		}
	}
	for _, binding := range c.KVNamespaces {
		if empty(binding.Binding, binding.ID) {
			return errors.New("Cloudflare Wrangler KV binding is incomplete")
		}
	}
	for _, binding := range c.D1Databases {
		if empty(binding.Binding, binding.DatabaseName, binding.DatabaseID) {
			return errors.New("Cloudflare Wrangler D1 binding is incomplete")
		}
	}
	for _, binding := range c.R2Buckets {
		if empty(binding.Binding, binding.BucketName) {
			return errors.New("Cloudflare Wrangler R2 binding is incomplete")
		}
	}
	if c.AI != nil && empty(c.AI.Binding) {
		return errors.New("Cloudflare Wrangler AI binding is incomplete")
	}
	for _, binding := range c.Vectorize {
		if empty(binding.Binding, binding.IndexName) {
			return errors.New("Cloudflare Wrangler Vectorize binding is incomplete")
		}
	}
	for _, binding := range c.DurableObjects {
		if empty(binding.Name, binding.ClassName) {
			return errors.New("Cloudflare Wrangler Durable Object binding is incomplete")
		}
	}
	for _, migration := range c.Migrations {
		if empty(migration.Tag) || len(migration.NewSQLiteClasses)+len(migration.NewClasses)+len(migration.RenamedClasses)+len(migration.DeletedClasses) == 0 {
			return errors.New("Cloudflare Wrangler migration is incomplete")
		}
		for _, rename := range migration.RenamedClasses {
			if empty(rename.From, rename.To) {
				return errors.New("Cloudflare Wrangler migration rename is incomplete")
			}
		}
	}
	return nil
}

func rejectDuplicateJSONKeys(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("Cloudflare Wrangler configuration contains a duplicate key")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("Cloudflare Wrangler configuration is invalid")
		}
	}
	if err := walk(); err != nil {
		return errors.New("Cloudflare Wrangler configuration is invalid or ambiguous")
	}
	return nil
}

func requireJSONEnd(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("Cloudflare Wrangler configuration has trailing content")
	}
	return nil
}

func canonicalAssets(input *assetsConfigWire) *AssetsConfig {
	if input == nil {
		return nil
	}
	return &AssetsConfig{
		Directory: input.Directory, Binding: input.Binding,
		RunWorkerFirst: input.RunWorkerFirst, NotFoundHandling: input.NotFoundHandling,
	}
}

func cloneAI(input *AIBinding) *AIBinding {
	if input == nil {
		return nil
	}
	copy := *input
	return &copy
}

func cloneMigrations(input []Migration) []Migration {
	output := make([]Migration, len(input))
	for index, migration := range input {
		output[index] = migration
		output[index].NewSQLiteClasses = append([]string(nil), migration.NewSQLiteClasses...)
		output[index].NewClasses = append([]string(nil), migration.NewClasses...)
		output[index].RenamedClasses = append([]ClassRename(nil), migration.RenamedClasses...)
		output[index].DeletedClasses = append([]string(nil), migration.DeletedClasses...)
	}
	return output
}

func cloneVars(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func empty(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}
