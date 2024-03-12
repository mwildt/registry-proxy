package main

import (
	"context"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"log"
	"ohrenpirat.de/container-scanning/pkg/configuration"
	"ohrenpirat.de/container-scanning/pkg/server"

	"sync"
)

func main() {
	var wg sync.WaitGroup
	endpointCount := 0
	fsCache, err := cache.NewFSCache(fsutils.CacheDir())
	if err != nil {
		log.Fatalf(err.Error())
	}

	info, err := fsCache.GetArtifact("asdlkjasd")
	if err != nil {
		log.Fatalf(err.Error())
	}
	log.Printf(info.Architecture)

	configuration.ForConfigCollection("registry.proxy.entrypoints", func(baseKey string, confSupplier configuration.ConfigSupplier) {
		address := confSupplier("service.address")
		if address == "" {
			log.Fatalf("service.address must be given foar basekey %s", baseKey)
		}
		upstreamUrl := confSupplier("service.upstream-url")
		if upstreamUrl == "" {
			log.Fatalf("service.upstream-url must be given foar basekey %s", baseKey)
		}

		registryServer := server.CreateNewServer(baseKey, upstreamUrl, func(ctx context.Context, name string, reference string) (report []byte, err error) {
			return []byte("FAILURE"), nil
			//return trivy.ScanDefault(ctx, name, reference)
		})
		wg.Add(1)
		endpointCount = endpointCount + 1
		go func() {
			err := registryServer.Run(address)
			log.Printf("%s: %s", baseKey, err.Error())
			wg.Done()
		}()
	})
	log.Printf("application startup finished. startet %d endpoints\n", endpointCount)
	wg.Wait()
}
