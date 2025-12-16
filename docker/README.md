# Dockerized Ghidra

## Build

From the root directory of your Ghidra release, run the following command.

```
./docker/build-docker-image.sh
```

This will build the ghidra docker image with a tag corresponding to the release version of Ghidra.


## The MODE environment variable

The Ghidra Docker Container supports the following `MODE`'s of execution:
- gui
- headless
- ghidra-server
- bsim
- bsim-server
- pyghidra

The `MODE` environment variable designates which entrypoint of Ghidra to execute. 

The `entrypoint.sh` script is executed upon container startup.

## Configuring a Container

Configuration of a container is done just as any other docker container would be configured. 
Volumes can be mounted, environment variables can be set, ports can be mapped from container to the host, and so on.
Configuration steps vary a lot based on what MODE the container is started with.

The base directory for Ghidra within the container is located at `/ghidra`. 
All of ghidra's default locations for files, configs, etc., are the same within that.
Ghidra is run as the user `ghidra` within the container, with uid `1001` and guid `1001`. 

The `ghidra` user only has permissions to the following directories inside the container:
- `/ghidra`
- `/home/ghidra`


When a container does not receive any arguments passed to it with the `docker run` command,
the corresponding Command Line Interface (CLI) for the `MODE` executed will display it's usage statement.

### Mapping Local Volumes to a Container

Volumes within the container may run into permission issues if the volumes are not accessible by users in the group id `1001`.

The default uid and guid for the container is `1001:1001`. Volumes that get mapped to the container should be accessible by this uid/guid.

Adding the host machine's user to the group `1001` on the host helps manage volumes that will be used in the container.
This can easily be done by executing `sudo usermod -aG 1001 <user>` on Linux.

### Example of Headless Mode

```
docker run \
    --env MODE=headless \
    --rm \
    --volume /path/to/myproject:/home/ghidra/myproject \
    --volume /path/to/mybinary:/home/ghidra/mybinary \
    ghidra/ghidra:<version> \
    /home/ghidra/myproject programFolder -import /home/ghidra/mybinary
```

Breaking this down line by line:
- `docker run` is going to start a docker container using the image `ghidra/ghidra<:<version>`
- `--env MODE=headless` configures the environment variable `MODE` within the container to be the value `headless`
- `--rm` removes the container after the command is complete
- `--volume /path/to/myproject:/home/ghidra/myproject` mounts the local volume 
	`/path/to/myproject` on the host to `/home/ghidra/myproject` within the container
- `--volume /path/to/mybinary:/home/ghidra/mybinary` mounts the local volume 
	`/path/to/mybinary` on the host to `/home/ghidra/mybinary` within the container
- `ghidra/ghidra:<version>` is the full reference for the docker image, where `ghidra/ghidra` is the group and name of the image, and `<version>` is the tag.
- `/home/ghidra/myproject programFolder -import /home/ghidra/mybinary` are arguments being passed to Ghidra's headless analyzer's command line interface

Passing no arguments will result in the usage of the headless analyzer being displayed. 

`/path/to/myproject` on the host must be accessible to guid `1001` with `rwx` permissions.

### Example of Gui Mode

Running Ghidra's Graphical User Interface (GUI) in the docker container is not a recommended method for running Ghidra.
GUI's are not a typical use case for dockerized applications.

```
docker run \
    --env MODE=gui \
    -it \
    --rm \
    --net host \
    --env DISPLAY \
    --volume "$HOME/.Xauthority:/home/ghidra/.Xauthority" \
    ghidra/ghidra:<version>
```

In this mode, the container relies on X11 forwarding to display the GUI. Configuration of X11 can vary, but in this case,
the host's Xauthority file is mounted into the container, the container is configured to use the host's network, and the DISPLAY
environment variable is passed to the container. This enables forwarding the GUI back to the host machine's display. Volumes 
containing binaries would still need to be mounted to the container as well as volumes for ghidra projects. 

The host's `.Xauthority` file must have appropriate permissions - assigned the group`:1001` with `rw` group permissions.


### Example of Ghidra Server Mode

```
docker run \
    --env MODE=ghidra-server \
    --rm \
    -it \
    --volume /path/to/my/repositories:/ghidra/repositories \
    --volume /path/to/my/configs/server.conf:/ghidra/server/server.conf \
    -p 13100:13100 \
    -p 13101:13101 \
    -p 13102:13102 \
    ghidra/ghidra:<version>
```

Volumes would need to be mounted to the server container to save the repositories, users, and also to configure the server as well.

To utilize svrAdmin, exec into the running ghidra server container (`docker exec -it <container-id> bash`) for a bash shell in the container. 
After exec'ing into the container, administration and management of the Ghidra server is the same as outside of a containerized environment.

To stop the container, execute the command `docker stop <container-id>`.

## Example of BSIM Server Mode

```
docker run \
    --env MODE=bsim-server \
    --rm \
    -it \
    --volume /path/to/my/datadir:/ghidra/bsim_datadir \
    -p 5432:5432 \
    ghidra/ghidra:<version> \
    /ghidra/bsim_datadir
```

`/ghidra/bsim_datadir` is the directory used to store bsim's data in the container. Other directories could be used on the container,
but make sure that the folder on the host machine has appropriate permissions, assigned the group `:1001`.

This example simply starts a bsim server. Configuring the bsim server and populating it with data 
could be done post start within the container in a similar way that ghidra server administration is done.
An administrator would have to exec into the running bsim server container (`docker exec -it <container-id> bash`), 
and after exec'ing into the container, administration and management of the Bsim server is the same as outside of a containerized environment.

To stop the container, execute the command `docker stop <container-id>`.

## Example of BSIM CLI Mode
```
docker run \
		--env MODE=bsim \
		--rm \
		 -it \
		 ghidra/ghidra:<version> \
		 generatesigs ghidra://ghidrasvr/demo /home/ghidra \
			 --bsim postgresql://bsimsvr/demo \
			 --commit --overwrite \
			 --user ghidra
```

In this example, the bsim CLI is used to connect to a ghidra server hosted on `ghidrasvr`, 
generate signatures for the `demo` repository in that ghidra server and save them to `/home/ghidra`. 
and then commit the signatures to the BSIM server hosted on `bsimsvr` in the `demo` database.


## Example of Pyghidra Gui Mode

Running Ghidra's Graphical User Interface (GUI) in the docker container is not a recommended method for running Ghidra.
GUI's are not a typical use case for dockerized applications.

```
docker run \
    --env MODE=pyghidra \
    -it \
    --rm \
    --net host \
    --env DISPLAY \
    --volume="$HOME/.Xauthority:/home/ghidra/.Xauthority:rw" \
    ghidra/ghidra:<version> -c
```
In this mode, the container relies on X11 forwarding to display the GUI. Configuration of X11 can vary, but in this case,
the host's Xauthority file is mounted into the container, the container is configured to use the host's network, and the DISPLAY
environment variable is passed to the container. This enables forwarding the GUI back to the host machine's display. Volumes 
containing binaries would still need to be mounted to the container as well as volumes for ghidra projects. 

The host's `.Xauthority` file must have appropriate permissions - owned by `:1001` with `rw` group permissions.


## Example of Pyghidra Headless Mode

```
docker run \
    --env MODE=pyghidra \
    --rm \
    --volume /path/to/myproject:/myproject \
    --volume /path/to/mybinary:/mybinary \
    ghidra/ghidra:<version> -H \
    /myproject programFolder -import /mybinary
```
Passing no arguments to the pyghidra headless analyzer will result in the help menu being displayed, just like the headless analyzer.

This use case is very similar to the headless mode's example with the added benefit of being able to utilize python3 for Ghidra Scripts.

Again, in this example, appropriate permissions and group assignment for `/path/to/myproject` and `/path/to/mybinary` are necessary 
in order to not run into permissions issues.

