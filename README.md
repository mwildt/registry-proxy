# Registry-Proxy

This project is a read-only proxy for an OCI container registry.
When downloading images, however, a Trivy image scan is performed first and the release of the image is refused if vulnerabilities of serverity HIGH or CRITIAL are present.
