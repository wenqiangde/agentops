package opscloudflarepayload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/shared"
	"github.com/cloudflare/cloudflare-go/v7/workers"
	"github.com/zeebo/blake3"
)

const cloudflareSDKVersion = "cloudflare-go/v7.7.0"

type sdkProductionTransport struct {
	baseURL string
}

func newSDKProductionTransport(baseURL string) sdkProductionTransport {
	return sdkProductionTransport{baseURL: baseURL}
}

func NewCloudflareClient(tokenProvider TokenProvider) (*Client, error) {
	return NewClient(tokenProvider, newSDKProductionTransport(""))
}

func (s sdkProductionTransport) Deploy(ctx context.Context, token []byte, request Request) (Evidence, error) {
	if ctx == nil || len(token) == 0 || !payloadDigestMatches(request.Payload, request.ExpectedSHA256) {
		return Evidence{}, errors.New("Cloudflare SDK production request is invalid")
	}
	var config CanonicalConfig
	if json.Unmarshal(request.Payload.Metadata, &config) != nil || config.validate() != nil ||
		config.Name != request.Worker || config.AccountID != request.AccountID || config.Main != request.Payload.MainModule {
		return Evidence{}, errors.New("Cloudflare SDK production metadata is invalid")
	}
	if !sdkProfileSupported(config, request.Payload) {
		return Evidence{}, errors.New("Cloudflare SDK production profile is unsupported")
	}

	options := []option.RequestOption{option.WithEnvironmentProduction(), option.WithAPIToken(string(token))}
	if s.baseURL != "" {
		options = append(options, option.WithBaseURL(s.baseURL))
	}
	service := workers.NewWorkerService(options...)
	started := time.Now().UTC()
	var versionID string
	if len(request.Payload.Assets) == 0 {
		files := make([]io.Reader, len(request.Payload.Modules))
		for index, module := range request.Payload.Modules {
			files[index] = &namedModuleReader{Reader: bytes.NewReader(module.Bytes), name: module.Name, contentType: module.Type}
		}
		version, err := service.Scripts.Versions.New(ctx, request.Worker, workers.ScriptVersionNewParams{
			AccountID: cloudflare.F(request.AccountID),
			Metadata: cloudflare.F(workers.ScriptVersionNewParamsMetadata{
				MainModule:         cloudflare.F(request.Payload.MainModule),
				CompatibilityDate:  cloudflare.F(config.CompatibilityDate),
				CompatibilityFlags: cloudflare.F(append([]string(nil), config.CompatibilityFlags...)),
			}),
			Files: cloudflare.F(files),
		})
		if err != nil || version == nil || version.ID == "" {
			return Evidence{}, errors.New("Cloudflare SDK version upload failed")
		}
		versionID = version.ID
	} else {
		completionToken, err := uploadAssets(ctx, service, request, config)
		if err != nil {
			return Evidence{}, err
		}
		versionParams, err := versionParamFor(config, request.Payload, completionToken)
		if err != nil {
			return Evidence{}, err
		}
		version, err := service.Beta.Workers.Versions.New(ctx, request.Worker, workers.BetaWorkerVersionNewParams{
			AccountID: cloudflare.F(request.AccountID),
			Deploy:    cloudflare.F(false),
			Version:   versionParams,
		})
		if err != nil || version == nil || version.ID == "" {
			return Evidence{}, errors.New("Cloudflare SDK version upload failed")
		}
		versionID = version.ID
	}
	deployment, err := service.Scripts.Deployments.New(ctx, request.Worker, workers.ScriptDeploymentNewParams{
		AccountID: cloudflare.F(request.AccountID),
		Deployment: workers.DeploymentParam{
			Strategy: cloudflare.F(workers.DeploymentStrategyPercentage),
			Versions: cloudflare.F([]workers.DeploymentVersionParam{{
				Percentage: cloudflare.F(100.0),
				VersionID:  cloudflare.F(versionID),
			}}),
		},
	})
	if err != nil || deployment == nil || deployment.ID == "" {
		return Evidence{}, errors.New("Cloudflare SDK deployment creation failed")
	}
	if len(config.Routes) > 0 || len(config.Crons) > 0 {
		if err := reconcileAndVerifyEndpoints(ctx, service, request, config, deployment.ID, versionID); err != nil {
			return Evidence{}, err
		}
	}
	return Evidence{
		ClientVersion: cloudflareSDKVersion,
		RequestID:     deployment.ID,
		VersionIDs:    []string{versionID},
		InputSHA256:   request.ExpectedSHA256,
		StartedAt:     started,
		FinishedAt:    time.Now().UTC(),
	}, nil
}

func (s sdkProductionTransport) Rollback(ctx context.Context, token []byte, request RollbackRequest) (Evidence, error) {
	if ctx == nil || len(token) == 0 || emptyRollbackRequest(request) || request.Timeout <= 0 {
		return Evidence{}, errors.New("Cloudflare SDK rollback request is invalid")
	}
	options := []option.RequestOption{option.WithEnvironmentProduction(), option.WithAPIToken(string(token))}
	if s.baseURL != "" {
		options = append(options, option.WithBaseURL(s.baseURL))
	}
	service := workers.NewWorkerService(options...)
	started := time.Now().UTC()
	deployment, err := service.Scripts.Deployments.New(ctx, request.Worker, workers.ScriptDeploymentNewParams{
		AccountID:  cloudflare.F(request.AccountID),
		Deployment: workers.DeploymentParam{Strategy: cloudflare.F(workers.DeploymentStrategyPercentage), Versions: cloudflare.F([]workers.DeploymentVersionParam{{Percentage: cloudflare.F(100.0), VersionID: cloudflare.F(request.TargetVersionID)}})},
	})
	if err != nil || deployment == nil || deployment.ID == "" || deployment.ID == request.PreviousDeploymentID {
		return Evidence{}, errors.New("Cloudflare SDK rollback deployment failed")
	}
	current, err := service.Scripts.Deployments.Get(ctx, request.Worker, deployment.ID, workers.ScriptDeploymentGetParams{AccountID: cloudflare.F(request.AccountID)})
	if err != nil || current == nil || current.ID != deployment.ID || len(current.Versions) != 1 || current.Versions[0].VersionID != request.TargetVersionID || current.Versions[0].Percentage != 100 {
		return Evidence{}, errors.New("Cloudflare SDK rollback identity verification failed")
	}
	return Evidence{ClientVersion: cloudflareSDKVersion, RequestID: current.ID, VersionIDs: []string{request.TargetVersionID}, InputSHA256: request.ExpectedSHA256, StartedAt: started, FinishedAt: time.Now().UTC()}, nil
}

func reconcileAndVerifyEndpoints(ctx context.Context, service *workers.WorkerService, request Request, config CanonicalConfig, deploymentID, versionID string) error {
	domains, err := service.Domains.List(ctx, workers.DomainListParams{AccountID: cloudflare.F(request.AccountID), Service: cloudflare.F(request.Worker)})
	if err != nil || domains == nil {
		return errors.New("Cloudflare SDK domain read failed")
	}
	desiredDomains := make(map[string]bool, len(config.Routes))
	for _, route := range config.Routes {
		if !route.CustomDomain {
			return errors.New("Cloudflare SDK zone route is unsupported")
		}
		desiredDomains[route.Pattern] = true
	}
	for _, domain := range domains.Result {
		if domain.Service == request.Worker && !desiredDomains[domain.Hostname] {
			if _, err := service.Domains.Delete(ctx, domain.ID, workers.DomainDeleteParams{AccountID: cloudflare.F(request.AccountID)}); err != nil {
				return errors.New("Cloudflare SDK stale domain removal failed")
			}
		}
	}
	for hostname := range desiredDomains {
		result, err := service.Domains.Update(ctx, workers.DomainUpdateParams{
			AccountID: cloudflare.F(request.AccountID), Hostname: cloudflare.F(hostname), Service: cloudflare.F(request.Worker), Environment: cloudflare.F("production"),
		})
		if err != nil || result == nil || result.ID == "" || result.Hostname != hostname || result.Service != request.Worker {
			return errors.New("Cloudflare SDK domain update failed")
		}
	}
	schedules := make([]workers.ScriptScheduleUpdateParamsBody, len(config.Crons))
	for index, cron := range config.Crons {
		schedules[index] = workers.ScriptScheduleUpdateParamsBody{Cron: cloudflare.F(cron)}
	}
	if _, err := service.Scripts.Schedules.Update(ctx, request.Worker, workers.ScriptScheduleUpdateParams{AccountID: cloudflare.F(request.AccountID), Body: schedules}); err != nil {
		return errors.New("Cloudflare SDK schedule update failed")
	}
	deployment, err := service.Scripts.Deployments.Get(ctx, request.Worker, deploymentID, workers.ScriptDeploymentGetParams{AccountID: cloudflare.F(request.AccountID)})
	if err != nil || deployment == nil || deployment.ID != deploymentID || len(deployment.Versions) != 1 || deployment.Versions[0].VersionID != versionID || deployment.Versions[0].Percentage != 100 {
		return errors.New("Cloudflare SDK deployment identity verification failed")
	}
	actualSchedules, err := service.Scripts.Schedules.Get(ctx, request.Worker, workers.ScriptScheduleGetParams{AccountID: cloudflare.F(request.AccountID)})
	if err != nil || actualSchedules == nil || !sameSchedules(config.Crons, actualSchedules.Schedules) {
		return errors.New("Cloudflare SDK schedule verification failed")
	}
	actualDomains, err := service.Domains.List(ctx, workers.DomainListParams{AccountID: cloudflare.F(request.AccountID), Service: cloudflare.F(request.Worker)})
	if err != nil || actualDomains == nil || !sameDomains(desiredDomains, actualDomains.Result, request.Worker) {
		return errors.New("Cloudflare SDK domain verification failed")
	}
	return nil
}

func sameSchedules(expected []string, actual []workers.ScriptScheduleGetResponseSchedule) bool {
	if len(expected) != len(actual) {
		return false
	}
	want := make(map[string]int, len(expected))
	for _, cron := range expected {
		want[cron]++
	}
	for _, schedule := range actual {
		want[schedule.Cron]--
		if want[schedule.Cron] < 0 {
			return false
		}
	}
	return true
}

func sameDomains(expected map[string]bool, actual []workers.DomainListResponse, worker string) bool {
	if len(expected) != len(actual) {
		return false
	}
	seen := make(map[string]bool, len(actual))
	for _, domain := range actual {
		if domain.Service != worker || !expected[domain.Hostname] || seen[domain.Hostname] {
			return false
		}
		seen[domain.Hostname] = true
	}
	return len(seen) == len(expected)
}

func versionParamFor(config CanonicalConfig, payload Payload, completionToken string) (workers.VersionParam, error) {
	modules := make([]workers.VersionModuleParam, len(payload.Modules))
	for index, module := range payload.Modules {
		modules[index] = workers.VersionModuleParam{
			Name: cloudflare.F(module.Name), ContentType: cloudflare.F(module.Type),
			ContentBase64: cloudflare.F(base64.StdEncoding.EncodeToString(module.Bytes)),
		}
	}
	bindings := make([]workers.VersionBindingsUnionParam, 0, 1+len(config.KVNamespaces)+len(config.D1Databases)+len(config.R2Buckets)+len(config.Vectorize)+len(config.DurableObjects)+len(config.Vars))
	if config.Assets != nil {
		bindings = append(bindings, workers.VersionBindingsWorkersBindingKindAssetsParam{
			Name: cloudflare.F(config.Assets.Binding), Type: cloudflare.F(workers.VersionBindingsWorkersBindingKindAssetsTypeAssets),
		})
	}
	for _, binding := range config.KVNamespaces {
		bindings = append(bindings, workers.VersionBindingsWorkersBindingKindKVNamespaceParam{Name: cloudflare.F(binding.Binding), NamespaceID: cloudflare.F(binding.ID), Type: cloudflare.F(workers.VersionBindingsWorkersBindingKindKVNamespaceTypeKVNamespace)})
	}
	for _, binding := range config.D1Databases {
		bindings = append(bindings, workers.VersionBindingsWorkersBindingKindD1Param{Name: cloudflare.F(binding.Binding), DatabaseID: cloudflare.F(binding.DatabaseID), Type: cloudflare.F(workers.VersionBindingsWorkersBindingKindD1TypeD1)})
	}
	for _, binding := range config.R2Buckets {
		bindings = append(bindings, workers.VersionBindingsWorkersBindingKindR2BucketParam{Name: cloudflare.F(binding.Binding), BucketName: cloudflare.F(binding.BucketName), Type: cloudflare.F(workers.VersionBindingsWorkersBindingKindR2BucketTypeR2Bucket)})
	}
	if config.AI != nil {
		bindings = append(bindings, workers.VersionBindingsWorkersBindingKindAIParam{Name: cloudflare.F(config.AI.Binding), Type: cloudflare.F(workers.VersionBindingsWorkersBindingKindAITypeAI)})
	}
	for _, binding := range config.Vectorize {
		bindings = append(bindings, workers.VersionBindingsWorkersBindingKindVectorizeParam{Name: cloudflare.F(binding.Binding), IndexName: cloudflare.F(binding.IndexName), Type: cloudflare.F(workers.VersionBindingsWorkersBindingKindVectorizeTypeVectorize)})
	}
	for _, binding := range config.DurableObjects {
		bindings = append(bindings, workers.VersionBindingsWorkersBindingKindDurableObjectNamespaceParam{Name: cloudflare.F(binding.Name), ClassName: cloudflare.F(binding.ClassName), Type: cloudflare.F(workers.VersionBindingsWorkersBindingKindDurableObjectNamespaceTypeDurableObjectNamespace)})
	}
	varNames := make([]string, 0, len(config.Vars))
	for name := range config.Vars {
		varNames = append(varNames, name)
	}
	sort.Strings(varNames)
	for _, name := range varNames {
		bindings = append(bindings, workers.VersionBindingsWorkersBindingKindPlainTextParam{Name: cloudflare.F(name), Text: cloudflare.F(config.Vars[name]), Type: cloudflare.F(workers.VersionBindingsWorkersBindingKindPlainTextTypePlainText)})
	}
	version := workers.VersionParam{
		MainModule: cloudflare.F(payload.MainModule), Modules: cloudflare.F(modules), Bindings: cloudflare.F(bindings),
		CompatibilityDate: cloudflare.F(config.CompatibilityDate), CompatibilityFlags: cloudflare.F(append([]string(nil), config.CompatibilityFlags...)),
	}
	if config.Assets != nil {
		version.Assets = cloudflare.F(workers.VersionAssetsParam{
			JWT: cloudflare.F(completionToken),
			Config: cloudflare.F(workers.VersionAssetsConfigParam{
				NotFoundHandling: cloudflare.F(workers.VersionAssetsConfigNotFoundHandling(config.Assets.NotFoundHandling)),
				RunWorkerFirst:   cloudflare.F[workers.VersionAssetsConfigRunWorkerFirstUnionParam](shared.UnionBool(config.Assets.RunWorkerFirst)),
			}),
		})
	}
	if len(config.Migrations) > 1 {
		return workers.VersionParam{}, errors.New("Cloudflare SDK multi-step migrations are unsupported")
	}
	if len(config.Migrations) == 1 {
		migration := config.Migrations[0]
		renames := make([]workers.SingleStepMigrationRenamedClassParam, len(migration.RenamedClasses))
		for index, rename := range migration.RenamedClasses {
			renames[index] = workers.SingleStepMigrationRenamedClassParam{From: cloudflare.F(rename.From), To: cloudflare.F(rename.To)}
		}
		version.Migrations = cloudflare.F[workers.VersionMigrationsUnionParam](workers.SingleStepMigrationParam{
			NewTag: cloudflare.F(migration.Tag), NewSqliteClasses: cloudflare.F(append([]string(nil), migration.NewSQLiteClasses...)),
			NewClasses: cloudflare.F(append([]string(nil), migration.NewClasses...)), DeletedClasses: cloudflare.F(append([]string(nil), migration.DeletedClasses...)), RenamedClasses: cloudflare.F(renames),
		})
	}
	return version, nil
}

func uploadAssets(ctx context.Context, service *workers.WorkerService, request Request, config CanonicalConfig) (string, error) {
	manifest := make(map[string]workers.ScriptAssetUploadNewParamsManifest, len(request.Payload.Assets))
	assets := make(map[string]Asset, len(request.Payload.Assets))
	for _, asset := range request.Payload.Assets {
		hash := assetManifestHash(asset)
		manifest["/"+strings.TrimPrefix(asset.Path, "/")] = workers.ScriptAssetUploadNewParamsManifest{
			Hash: cloudflare.F(hash), Size: cloudflare.F(int64(len(asset.Bytes))),
		}
		assets[hash] = asset
	}
	session, err := service.Scripts.Assets.Upload.New(ctx, request.Worker, workers.ScriptAssetUploadNewParams{
		AccountID: cloudflare.F(request.AccountID), Manifest: cloudflare.F(manifest),
	})
	if err != nil || session == nil || session.JWT == "" {
		return "", errors.New("Cloudflare SDK asset session failed")
	}
	for _, bucket := range session.Buckets {
		body := make(map[string]string, len(bucket))
		for _, hash := range bucket {
			asset, ok := assets[hash]
			if !ok {
				return "", errors.New("Cloudflare SDK asset session requested an unknown asset")
			}
			body[hash] = base64.StdEncoding.EncodeToString(asset.Bytes)
		}
		result, err := service.Assets.Upload.New(ctx, workers.AssetUploadNewParams{
			AccountID: cloudflare.F(request.AccountID), Base64: cloudflare.F(workers.AssetUploadNewParamsBase64True), Body: body,
		}, option.WithHeader("Authorization", "Bearer "+session.JWT))
		if err != nil || result == nil || result.JWT == "" {
			return "", errors.New("Cloudflare SDK asset upload failed")
		}
		session.JWT = result.JWT
	}
	return session.JWT, nil
}

func assetManifestHash(asset Asset) string {
	extension := strings.TrimPrefix(path.Ext(asset.Path), ".")
	encoded := base64.StdEncoding.EncodeToString(asset.Bytes)
	sum := blake3.Sum256([]byte(encoded + extension))
	return fmt.Sprintf("%x", sum[:16])
}

type namedModuleReader struct {
	*bytes.Reader
	name        string
	contentType string
}

func (r *namedModuleReader) Name() string        { return r.name }
func (r *namedModuleReader) ContentType() string { return r.contentType }

func sdkProfileSupported(config CanonicalConfig, payload Payload) bool {
	assetsMatch := (len(payload.Assets) == 0 && config.Assets == nil) || (len(payload.Assets) > 0 && config.Assets != nil)
	if !assetsMatch || len(config.Migrations) > 1 {
		return false
	}
	for _, route := range config.Routes {
		if !route.CustomDomain {
			return false
		}
	}
	return true
}
