package main

import (
	"log"
	"ohrenpirat.de/container-scanning/pkg/server"
	"ohrenpirat.de/container-scanning/pkg/trivy"

	"ohrenpirat.de/container-scanning/pkg/configuration"

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

		registryServer := server.CreateNewServer(baseKey, upstreamUrl, trivy.ScanDefault)
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
