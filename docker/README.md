# Dockerized Ghidra

This document provides comprehensive instructions for building, running, and managing Ghidra in Docker containers.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Building the Docker Image](#building-the-docker-image)
- [Container Modes](#container-modes)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Docker Compose](#docker-compose)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Best Practices](#best-practices)
- [Performance Tuning](#performance-tuning)
- [Advanced Topics](#advanced-topics)

## Prerequisites

Before building and running Ghidra in Docker, ensure you have:

- **Docker** version 20.10 or later installed and running
- **Docker Compose** (optional, for multi-container setups) version 2.0 or later
- A **built Ghidra release** (not source code) - the Docker image must be built from a release
- Sufficient disk space (at least 5GB free for the image and build process)
- On Linux: Appropriate permissions to run Docker commands (typically requires being in the `docker` group)

### Verifying Docker Installation

```bash
docker --version
docker info
```

## Quick Start

The fastest way to get started:

```bash
# From the root of your Ghidra release directory
./docker/build-docker-image.sh

# Run headless analysis
docker run --rm \
    --env MODE=headless \
    --volume $(pwd)/myproject:/home/ghidra/myproject \
    --volume $(pwd)/mybinary:/home/ghidra/mybinary \
    ghidra/ghidra:<version> \
    /home/ghidra/myproject programFolder -import /home/ghidra/mybinary
```

## Building the Docker Image

### Basic Build

From the root directory of your Ghidra release, run:

```bash
./docker/build-docker-image.sh
```

This script will:
1. Verify Docker is installed
2. Check that you're in a built Ghidra release directory
3. Extract version information from `Ghidra/application.properties`
4. Build the Docker image with tag `ghidra/ghidra:<version>_<release>`

### Manual Build

If you prefer to build manually:

```bash
# Get version information
source <(sed 's/\.\|\(=.*\)/_\1/g;s/_=/=/' Ghidra/application.properties)
VERSION=${application_version}
RELEASE=${application_release_name}
TAG=${VERSION}_${RELEASE}

# Build the image
docker build -f docker/Dockerfile -t ghidra/ghidra:$TAG .
```

### Build Options

The Dockerfile uses multi-stage builds for optimization:
- **base**: Minimal runtime dependencies
- **build**: Build-time dependencies (Gradle, compilers, etc.)
- **runtime**: Final optimized image

### Verifying the Build

After building, verify the image exists:

```bash
docker images | grep ghidra
```

You should see an image tagged as `ghidra/ghidra:<version>_<release>`.

## Container Modes

The Ghidra Docker container supports multiple execution modes via the `MODE` environment variable:

| Mode | Description | Use Case |
|------|-------------|----------|
| `headless` | Command-line analysis without GUI | Automated analysis, CI/CD pipelines |
| `gui` | Graphical user interface | Interactive analysis (not recommended in Docker) |
| `ghidra-server` | Ghidra Server for multi-user collaboration | Team environments, shared repositories |
| `bsim` | Binary Similarity Indexing CLI | Generating and querying function signatures |
| `bsim-server` | BSIM database server | Hosting BSIM PostgreSQL database |
| `pyghidra` | Python-based Ghidra interface | Python scripting and automation |

The `entrypoint.sh` script executes upon container startup and routes to the appropriate Ghidra component based on `MODE`.

## Configuration

### Container User and Permissions

Ghidra runs as user `ghidra` (UID/GID `1001:1001`) inside the container for security reasons.

**Writable directories:**
- `/ghidra` - Ghidra installation directory
- `/home/ghidra` - User home directory (recommended for projects)

### Volume Mounting

When mounting volumes, ensure proper permissions:

**Linux:**
```bash
# Add your user to group 1001
sudo usermod -aG 1001 $USER

# Set permissions on directories you'll mount
sudo chown -R :1001 /path/to/myproject
sudo chmod -R g+w /path/to/myproject
```

**macOS/Windows:**
Docker Desktop handles permissions automatically, but you may need to adjust file permissions within the container.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MODE` | `gui` | Execution mode (see [Container Modes](#container-modes)) |
| `MAXMEM` | `2G` | Maximum Java heap size (e.g., `4G`, `8192M`) |
| `LAUNCH_MODE` | `fg` | Launch mode: `fg` (foreground) or `bg` (background) |
| `DEBUG_ADDRESS` | `127.0.0.1:13002` | Debug server address for headless mode |
| `VMARG_LIST` | Varies by mode | Additional JVM arguments |
| `DISPLAY` | (unset) | X11 display for GUI mode |

### Port Mapping

Common ports used by Ghidra services:

| Service | Container Port | Description |
|---------|---------------|-------------|
| Ghidra Server | 13100-13102 | Server communication ports |
| BSIM Server | 5432 | PostgreSQL database port |
| Debug Server | 13002 | Remote debugging port |

Example port mapping:
```bash
-p 13100:13100 -p 13101:13101 -p 13102:13102
```

## Usage Examples

### Headless Mode

Headless mode is ideal for automated analysis, CI/CD pipelines, and batch processing.

#### Basic Analysis

```bash
docker run \
    --env MODE=headless \
    --rm \
    --volume /path/to/myproject:/home/ghidra/myproject \
    --volume /path/to/mybinary:/home/ghidra/mybinary \
    ghidra/ghidra:<version> \
    /home/ghidra/myproject programFolder -import /home/ghidra/mybinary
```

**Command breakdown:**
- `--env MODE=headless` - Sets execution mode to headless analyzer
- `--rm` - Automatically removes container after execution
- `--volume` - Mounts host directories into container
- Arguments after image name are passed to `analyzeHeadless`

#### With Analysis Scripts

```bash
docker run \
    --env MODE=headless \
    --rm \
    --volume /path/to/myproject:/home/ghidra/myproject \
    --volume /path/to/mybinary:/home/ghidra/mybinary \
    --volume /path/to/scripts:/home/ghidra/scripts \
    ghidra/ghidra:<version> \
    /home/ghidra/myproject programFolder \
    -import /home/ghidra/mybinary \
    -scriptPath /home/ghidra/scripts \
    -postScript MyScript.java
```

#### With Custom Memory Settings

```bash
docker run \
    --env MODE=headless \
    --env MAXMEM=8G \
    --rm \
    --volume /path/to/myproject:/home/ghidra/myproject \
    --volume /path/to/mybinary:/home/ghidra/mybinary \
    ghidra/ghidra:<version> \
    /home/ghidra/myproject programFolder -import /home/ghidra/mybinary
```

#### Batch Processing Multiple Binaries

```bash
for binary in /path/to/binaries/*; do
    docker run \
        --env MODE=headless \
        --rm \
        --volume /path/to/myproject:/home/ghidra/myproject \
        --volume "$binary:/home/ghidra/$(basename $binary)" \
        ghidra/ghidra:<version> \
        /home/ghidra/myproject "$(basename $binary)" -import "/home/ghidra/$(basename $binary)"
done
```

**Note:** The project directory on the host must be accessible to GID `1001` with `rwx` permissions. Passing no arguments displays the headless analyzer usage.

### GUI Mode

> **⚠️ Warning:** Running Ghidra's GUI in Docker is not recommended. GUI applications are not typical use cases for containerized applications. Consider using headless mode or running Ghidra natively for GUI access.

If you must run the GUI in Docker, you'll need X11 forwarding:

#### Linux with X11

```bash
# Allow X11 connections (one-time setup)
xhost +local:docker

# Run GUI
docker run \
    --env MODE=gui \
    -it \
    --rm \
    --net host \
    --env DISPLAY=$DISPLAY \
    --volume "$HOME/.Xauthority:/home/ghidra/.Xauthority:ro" \
    --volume /path/to/myproject:/home/ghidra/myproject \
    --volume /path/to/mybinary:/home/ghidra/mybinary \
    ghidra/ghidra:<version>
```

**Requirements:**
- X11 server running on host
- `.Xauthority` file must be readable by GID `1001`
- `DISPLAY` environment variable set on host

**Setting Xauthority permissions:**
```bash
chgrp 1001 ~/.Xauthority
chmod g+r ~/.Xauthority
```

#### macOS with XQuartz

```bash
# Install XQuartz if not already installed
brew install --cask xquartz

# Allow connections from Docker
xhost + 127.0.0.1

# Run GUI
docker run \
    --env MODE=gui \
    -it \
    --rm \
    --env DISPLAY=host.docker.internal:0 \
    --volume /path/to/myproject:/home/ghidra/myproject \
    ghidra/ghidra:<version>
```


### Ghidra Server Mode

Ghidra Server enables multi-user collaboration with shared repositories.

#### Basic Server Setup

```bash
docker run \
    --env MODE=ghidra-server \
    -d \
    --name ghidra-server \
    --restart unless-stopped \
    --volume /path/to/repositories:/ghidra/repositories \
    --volume /path/to/server.conf:/ghidra/server/server.conf \
    -p 13100:13100 \
    -p 13101:13101 \
    -p 13102:13102 \
    ghidra/ghidra:<version>
```

**Important volumes:**
- `/ghidra/repositories` - Server repositories (must persist)
- `/ghidra/server/server.conf` - Server configuration file
- `/ghidra/server/svrAdmin` - Server admin tools (optional)

#### Server Administration

Access the server administration tools:

```bash
# Get container ID
docker ps | grep ghidra-server

# Execute into container
docker exec -it <container-id> bash

# Inside container, use svrAdmin
/ghidra/server/svrAdmin
```

#### Viewing Server Logs

```bash
docker logs -f ghidra-server
```

#### Stopping the Server

```bash
docker stop ghidra-server
docker rm ghidra-server  # if you used --rm, this isn't needed
```

#### Server Configuration

Create `server.conf` on your host:

```properties
# Example server.conf
ghidra.server.port=13100
ghidra.server.ssl.port=13101
ghidra.server.rmi.port=13102
```

Mount it when starting the container as shown above.

### BSIM Server Mode

BSIM (Binary Similarity Indexing) Server hosts a PostgreSQL database for function signature storage and querying.

#### Starting BSIM Server

```bash
docker run \
    --env MODE=bsim-server \
    -d \
    --name bsim-server \
    --restart unless-stopped \
    --volume /path/to/bsim_datadir:/ghidra/bsim_datadir \
    -p 5432:5432 \
    ghidra/ghidra:<version> \
    /ghidra/bsim_datadir
```

**Important:**
- The data directory must be accessible to GID `1001`
- Port `5432` is the PostgreSQL default port
- The directory path is passed as an argument to the server

#### BSIM Server Administration

```bash
# Access server administration
docker exec -it bsim-server bash

# Inside container, use bsim_ctl commands
/ghidra/support/bsim_ctl
```

#### Viewing BSIM Logs

```bash
docker logs -f bsim-server
```

### BSIM CLI Mode

Use BSIM CLI to generate signatures and query the database.

#### Generate Signatures from Ghidra Server

```bash
docker run \
    --env MODE=bsim \
    --rm \
    --network ghidra-network \
    ghidra/ghidra:<version> \
    generatesigs ghidra://ghidrasvr/demo /home/ghidra \
        --bsim postgresql://bsimsvr/demo \
        --commit --overwrite \
        --user ghidra
```

**Command explanation:**
- `generatesigs` - Generate function signatures
- `ghidra://ghidrasvr/demo` - Source Ghidra server and repository
- `/home/ghidra` - Output directory for signatures
- `--bsim postgresql://bsimsvr/demo` - Target BSIM database
- `--commit` - Commit signatures to database
- `--overwrite` - Overwrite existing signatures

#### Query BSIM Database

```bash
docker run \
    --env MODE=bsim \
    --rm \
    --network ghidra-network \
    ghidra/ghidra:<version> \
    query --bsim postgresql://bsimsvr/demo \
        --function-name "main" \
        --similarity 0.8
```


### PyGhidra Mode

PyGhidra provides Python 3 scripting capabilities for Ghidra automation.

#### PyGhidra Headless Mode

```bash
docker run \
    --env MODE=pyghidra \
    --rm \
    --volume /path/to/myproject:/myproject \
    --volume /path/to/mybinary:/mybinary \
    --volume /path/to/scripts:/scripts \
    ghidra/ghidra:<version> -H \
    /myproject programFolder -import /mybinary \
    -scriptPath /scripts \
    -postScript my_script.py
```

**Benefits over standard headless:**
- Full Python 3 support (not just Jython)
- Access to modern Python libraries
- Better integration with Python tooling

#### PyGhidra Interactive Mode

```bash
docker run \
    --env MODE=pyghidra \
    -it \
    --rm \
    --volume /path/to/myproject:/myproject \
    ghidra/ghidra:<version> -i
```

#### PyGhidra GUI Mode

> **⚠️ Warning:** Not recommended. See [GUI Mode](#gui-mode) warnings.

```bash
docker run \
    --env MODE=pyghidra \
    -it \
    --rm \
    --net host \
    --env DISPLAY=$DISPLAY \
    --volume="$HOME/.Xauthority:/home/ghidra/.Xauthority:ro" \
    --volume /path/to/myproject:/myproject \
    ghidra/ghidra:<version> -c
```

#### Running Python Scripts

```bash
docker run \
    --env MODE=pyghidra \
    --rm \
    --volume /path/to/myproject:/myproject \
    --volume /path/to/script.py:/script.py \
    ghidra/ghidra:<version> -H \
    /myproject programFolder \
    -scriptPath / \
    -postScript script.py
```

## Docker Compose

Docker Compose simplifies multi-container setups. Here are example configurations:

### Ghidra Server with BSIM

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  ghidra-server:
    image: ghidra/ghidra:<version>
    container_name: ghidra-server
    environment:
      - MODE=ghidra-server
    volumes:
      - ./repositories:/ghidra/repositories
      - ./server.conf:/ghidra/server/server.conf
    ports:
      - "13100:13100"
      - "13101:13101"
      - "13102:13102"
    restart: unless-stopped
    networks:
      - ghidra-network

  bsim-server:
    image: ghidra/ghidra:<version>
    container_name: bsim-server
    environment:
      - MODE=bsim-server
    volumes:
      - ./bsim_datadir:/ghidra/bsim_datadir
    ports:
      - "5432:5432"
    command: /ghidra/bsim_datadir
    restart: unless-stopped
    networks:
      - ghidra-network

networks:
  ghidra-network:
    driver: bridge
```

**Usage:**
```bash
docker-compose up -d
docker-compose logs -f
docker-compose down
```

### Development Environment

```yaml
version: '3.8'

services:
  ghidra-headless:
    image: ghidra/ghidra:<version>
    environment:
      - MODE=headless
      - MAXMEM=4G
    volumes:
      - ./projects:/home/ghidra/projects
      - ./binaries:/home/ghidra/binaries
      - ./scripts:/home/ghidra/scripts
    command: /home/ghidra/projects myproject -import /home/ghidra/binaries/mybinary
    working_dir: /home/ghidra
    networks:
      - ghidra-network

networks:
  ghidra-network:
    driver: bridge
```

## Troubleshooting

### Common Issues and Solutions

#### Permission Denied Errors

**Problem:** Container cannot write to mounted volumes.

**Solution:**
```bash
# Check current permissions
ls -la /path/to/mounted/directory

# Fix permissions (Linux)
sudo chown -R :1001 /path/to/mounted/directory
sudo chmod -R g+w /path/to/mounted/directory

# Or add your user to group 1001
sudo usermod -aG 1001 $USER
# Log out and back in for changes to take effect
```

#### Container Exits Immediately

**Problem:** Container starts and immediately stops.

**Solution:**
- Check container logs: `docker logs <container-id>`
- Ensure `MODE` environment variable is set correctly
- Verify you're passing required arguments for the selected mode
- For headless mode, ensure project and binary paths are correct

#### Out of Memory Errors

**Problem:** Java heap space errors or container being killed.

**Solution:**
```bash
# Increase MAXMEM
docker run --env MAXMEM=8G ...

# Or limit container memory
docker run --memory=10g --env MAXMEM=8G ...
```

#### X11 Forwarding Not Working (GUI Mode)

**Problem:** GUI doesn't display or shows permission errors.

**Solution:**
```bash
# Check X11 is running
echo $DISPLAY

# Allow Docker to connect (Linux)
xhost +local:docker

# Fix Xauthority permissions
chgrp 1001 ~/.Xauthority
chmod g+r ~/.Xauthority

# For macOS with XQuartz
xhost + 127.0.0.1
```

#### Port Already in Use

**Problem:** Port binding fails because port is already in use.

**Solution:**
```bash
# Find process using the port
sudo lsof -i :13100

# Use different host port
docker run -p 13110:13100 ...
```

#### Build Fails with "application.properties not found"

**Problem:** Build script can't find version information.

**Solution:**
- Ensure you're building from a **release** directory, not source
- Verify `Ghidra/application.properties` exists
- Run build script from the root of the release directory

#### Slow Performance

**Problem:** Container operations are slow.

**Solutions:**
- Use named volumes instead of bind mounts for better performance
- Ensure Docker has sufficient resources allocated
- Use `--memory` and `--cpus` limits appropriately
- Consider using Docker's build cache

### Debugging Tips

#### Inspect Running Container

```bash
# Get container ID
docker ps

# Execute into container
docker exec -it <container-id> bash

# Check environment variables
docker exec <container-id> env

# View logs
docker logs -f <container-id>
```

#### Test Container Entrypoint

```bash
# Override entrypoint to test
docker run --entrypoint /bin/bash -it ghidra/ghidra:<version>

# Inside container, test entrypoint manually
MODE=headless /ghidra/docker/entrypoint.sh --help
```

#### Verbose Logging

```bash
# Enable Java verbose logging
docker run --env VMARG_LIST="-Djava.util.logging.config.file=/ghidra/support/logging.properties" ...
```

## Security Considerations

### Running as Non-Root

The container runs as user `ghidra` (UID 1001) instead of root, which is a security best practice.

### Network Security

- **Don't expose ports unnecessarily:** Only map ports you actually need
- **Use Docker networks:** Isolate containers using Docker networks instead of `--net host`
- **Firewall rules:** Configure host firewall to restrict access to exposed ports

### Volume Security

- **Read-only mounts:** Use `:ro` suffix for volumes that don't need write access
- **Sensitive data:** Be careful mounting directories containing sensitive information
- **Permissions:** Ensure mounted volumes have appropriate permissions

### Image Security

- **Base image:** The image uses Alpine Linux, which is minimal and security-focused
- **Updates:** Regularly rebuild images to include security updates
- **Scanning:** Use tools like `docker scan` or Trivy to scan images for vulnerabilities

```bash
# Scan image for vulnerabilities
docker scan ghidra/ghidra:<version>
```

### Best Security Practices

1. **Don't run GUI mode in production** - Use headless mode instead
2. **Limit container resources** - Use `--memory` and `--cpus` limits
3. **Use secrets management** - Don't hardcode credentials in Dockerfiles
4. **Regular updates** - Keep Docker and images updated
5. **Network isolation** - Use Docker networks to isolate services
6. **Read-only root filesystem** - Consider `--read-only` flag for enhanced security

## Best Practices

### Resource Management

```bash
# Set memory limits
docker run --memory=8g --env MAXMEM=6G ...

# Limit CPU usage
docker run --cpus="2.0" ...

# Combine both
docker run --memory=8g --cpus="2.0" --env MAXMEM=6G ...
```

### Volume Management

```bash
# Use named volumes for better performance
docker volume create ghidra-projects
docker run --volume ghidra-projects:/home/ghidra/projects ...

# Use read-only mounts when possible
docker run --volume /readonly/data:/data:ro ...
```

### Container Lifecycle

```bash
# Use restart policies for long-running services
docker run --restart unless-stopped ...

# Clean up stopped containers
docker container prune

# Remove unused volumes
docker volume prune
```

### Logging

```bash
# Use logging drivers for better log management
docker run --log-driver json-file --log-opt max-size=10m --log-opt max-file=3 ...

# View logs with timestamps
docker logs -t <container-id>
```

### Multi-Stage Builds

The Dockerfile already uses multi-stage builds. When creating custom images:

```dockerfile
# Build stage
FROM ghidra/ghidra:<version> AS builder
# ... build steps ...

# Runtime stage
FROM ghidra/ghidra:<version>
COPY --from=builder /built/artifacts /ghidra/
```

## Performance Tuning

### Java Memory Settings

Adjust `MAXMEM` based on your workload:

```bash
# Small binaries (< 10MB)
--env MAXMEM=2G

# Medium binaries (10-100MB)
--env MAXMEM=4G

# Large binaries (> 100MB)
--env MAXMEM=8G

# Very large binaries or batch processing
--env MAXMEM=16G
```

**Note:** Container memory should be at least 1-2GB more than `MAXMEM`.

### JVM Tuning

Customize JVM arguments for your workload:

```bash
# For analysis-heavy workloads
--env VMARG_LIST="-XX:+UseG1GC -XX:MaxGCPauseMillis=200"

# For memory-constrained environments
--env VMARG_LIST="-XX:+UseSerialGC -Xms1G"
```

### Parallel Processing

For batch operations, run multiple containers in parallel:

```bash
# Process binaries in parallel (adjust -P for your system)
find /binaries -type f | xargs -n 1 -P 4 -I {} \
  docker run --rm --env MODE=headless \
    --volume /projects:/projects \
    --volume {}:/binary \
    ghidra/ghidra:<version> \
    /projects project -import /binary
```

### Storage Optimization

- Use SSD storage for project directories
- Consider using Docker volumes on fast storage
- Regularly clean up old projects and temporary files

## Advanced Topics

### Custom Entrypoint Scripts

Create custom entrypoint scripts for specialized workflows:

```bash
#!/bin/bash
# custom-entrypoint.sh
export MODE=headless
export MAXMEM=4G

# Pre-processing
echo "Starting analysis..."

# Run Ghidra
/ghidra/docker/entrypoint.sh "$@"

# Post-processing
echo "Analysis complete"
```

### Building Custom Images

Extend the base image for custom configurations:

```dockerfile
FROM ghidra/ghidra:<version>

# Install additional tools
USER root
RUN apk add --no-cache vim curl

# Add custom scripts
COPY my-scripts/ /home/ghidra/scripts/
RUN chown -R ghidra:ghidra /home/ghidra/scripts

USER ghidra
```

### Integration with CI/CD

Example GitHub Actions workflow:

```yaml
name: Analyze Binary

on: [push]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Ghidra Analysis
        run: |
          docker run --rm \
            --env MODE=headless \
            --volume $PWD:/workspace \
            ghidra/ghidra:latest \
            /workspace/project program -import /workspace/binary
```

### Health Checks

Add health checks for long-running containers:

```yaml
# docker-compose.yml
services:
  ghidra-server:
    image: ghidra/ghidra:<version>
    healthcheck:
      test: ["CMD", "pgrep", "-f", "ghidraSvr"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Monitoring

Monitor container resource usage:

```bash
# Real-time stats
docker stats <container-id>

# Export metrics
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"
```

## Additional Resources

- [Ghidra Documentation](https://ghidra-sre.org/)
- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Ghidra GitHub Repository](https://github.com/NationalSecurityAgency/ghidra)

## Getting Help

- **GitHub Issues:** Report bugs and request features at [Ghidra Issues](https://github.com/NationalSecurityAgency/ghidra/issues)
- **Documentation:** Check the main [Ghidra Documentation](https://ghidra-sre.org/)
- **Community:** Join discussions in the Ghidra community forums

---

**Last Updated:** See Git history for latest changes  
**Maintained by:** Ghidra Development Team

