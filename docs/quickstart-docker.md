# Quickstart (Docker)

## Build
`ash
docker build -t threat-research-mcp -f deployment/docker/Dockerfile .
`

## Run
`ash
docker run --rm -it threat-research-mcp
`

For compose-based local stacks, see deployment/docker/docker-compose.yml.
