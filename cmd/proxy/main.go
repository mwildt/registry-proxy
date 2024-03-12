package main

import (
	"context"
	"fmt"
	"log"
	"ohrenpirat.de/container-scanning/pkg/configuration"
	"ohrenpirat.de/container-scanning/pkg/server"
	"ohrenpirat.de/container-scanning/pkg/trivy"
	"sync"
)

func main() {
	var wg sync.WaitGroup
	endpointCount := 0

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
			regName := confSupplier("service.registry")
			imageName := fmt.Sprintf("%s/%s:%s", regName, name, reference)
			log.Printf("scan image with trivy %s", imageName)
			return trivy.ScanDefault(ctx, imageName)
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
