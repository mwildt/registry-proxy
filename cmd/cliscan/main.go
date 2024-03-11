package main

import (
	"context"
	"fmt"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
	"log"
	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB
	"os"
	"path"
	"time"
)

const defaultDBRepository = "ghcr.io/aquasecurity/trivy-db"
const defaultJavaDBRepository = "ghcr.io/aquasecurity/trivy-java-db"

func main() {

	if err := scan(context.Background(), "localhost:5000/aquasec/trivy"); err != nil {
		log.Fatal(err)
	}

	//if err := scan(context.Background(), "dependencytrack/apiserver:4.10.1"); err != nil {
	//	log.Fatal(err)
	//}
	//if err := scan(context.Background(), "dependencytrack/frontend:latest"); err != nil {
	//	log.Fatal(err)
	//}
	//if err := scan(context.Background(), "registry.suse.com/bci/bci-base:15.5"); err != nil {
	//	log.Fatal(err)
	//}
	//if err := scan(context.Background(), "registry.suse.com/bci/bci-minimal:15.5"); err != nil {
	//	log.Fatal(err)
	//}
	//if err := scan(context.Background(), "registry.suse.com/bci/bci-micro:15.5"); err != nil {
	//	log.Fatal(err)
	//}
	//if err := scan(context.Background(), "registry.suse.com/bci/bci-base:15.5.36.5.75"); err != nil {
	//	log.Fatal(err)
	//}

	//if err := scan(context.Background(), "registry.suse.com/bci/openjdk-devel:latest@sha256:d1830d8714594ff1563ac49d5c50693dbc33ac5373f66bc6a29afbc3eab48900"); err != nil {
	//	log.Fatal(err)
	//}

	//if err := scan(context.Background(), "openjdk:23-jdk"); err != nil {
	//	log.Fatal(err)
	//}

}

func scan(context context.Context, scanTarget string) (err error) {

	registryOptions, err := flag.NewRegistryFlagGroup().ToOptions()
	if err != nil {
		log.Fatal(err)
	}

	options := flag.Options{
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

	dirPath := path.Join(
		"reports",
		scanTarget,
	)

	err = os.MkdirAll(dirPath, os.ModePerm)
	if err != nil {
		fmt.Println("Fehler beim Erstellen des Verzeichnisses:", err)
		return
	}
	file, err := os.OpenFile(path.Join(dirPath, "report.tbl.txt"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)

	options.SetOutputWriter(file)

	return artifact.Run(context, options, artifact.TargetContainerImage)

}
