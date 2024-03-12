package configuration

import (
	"fmt"
	"os"
	"strings"
)

type ConfigSupplier func(string) string

func ForConfigCollection(baseName string, callback func(string, ConfigSupplier)) {
	baseKeys := strings.Split(os.Getenv(baseName), ",")
	for _, baseKey := range baseKeys {
		supplier := func(key string) string {
			return os.Getenv(fmt.Sprintf("%s.%s.%s", baseName, baseKey, key))
		}
		callback(baseKey, supplier)
	}
}
