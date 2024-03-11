package trivy

import (
	"bytes"
	"context"
	"fmt"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
	"os"
	"path"
	"time"
)

const defaultDBRepository = "ghcr.io/aquasecurity/trivy-db"
const defaultJavaDBRepository = "ghcr.io/aquasecurity/trivy-java-db"

func defaultOptions(scanTarget string) flag.Options {
	registryOptions, _ := flag.NewRegistryFlagGroup().ToOptions()

	return flag.Options{
		GlobalOptions: flag.GlobalOptions{
			Timeout:  time.Minute * 10,
			CacheDir: "./cache",
		},
		ReportOptions: flag.ReportOptions{
			//Format: types.FormatJSON,
			Format: types.FormatTable,
			Severities: []dbTypes.Severity{
				dbTypes.SeverityCritical,
				dbTypes.SeverityHigh,
				dbTypes.SeverityMedium,
				dbTypes.SeverityLow,
				dbTypes.SeverityUnknown,
			},
		},
		ScanOptions: flag.ScanOptions{
			Target: scanTarget,
			Scanners: types.Scanners{
				types.VulnerabilityScanner,
				//types.SecretScanner,
			},
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnType: types.VulnTypes,
		},
		RegistryOptions: registryOptions,
		DBOptions: flag.DBOptions{
			DBRepository:     defaultDBRepository,
			JavaDBRepository: defaultJavaDBRepository,
		},
		ImageOptions: flag.ImageOptions{
			ImageSources: ftypes.ImageSources{ /*ftypes.DockerImageSource,*/ ftypes.RemoteImageSource},
		},
	}
}

func ScanDefault(context context.Context, name string, reference string) (report []byte, err error) {
	scanTarget := fmt.Sprintf("%s:%s", name, reference)
	options := defaultOptions(scanTarget)
	dirPath := path.Join(
		"reports",
		scanTarget,
	)
	err = os.MkdirAll(dirPath, os.ModePerm)
	if err != nil {
		fmt.Println("Fehler beim Erstellen des Verzeichnisses:", err)
		return
	}
	var buffer []byte
	writer := bytes.NewBuffer(buffer)
	options.SetOutputWriter(writer)
	err = artifact.Run(context, options, artifact.TargetContainerImage)
	if err != nil {
		return report, err
	}
	return writer.Bytes(), nil
}
