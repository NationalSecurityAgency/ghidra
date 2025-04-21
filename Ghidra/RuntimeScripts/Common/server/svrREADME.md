# Ghidra Server README

## Table of Contents
* [Introduction](#introduction)
* [Java Runtime Environment](#java-runtime-environment)
* [Server Configuration](#server-configuration)
* [Server Logs](#server-logs)
* [Server Memory Considerations](#server-memory-considerations)
* [Note regarding use of DNS (name lookup service)](#note-regarding-use-of-dns-name-lookup-service)
* [User Authentication](#user-authentication)
* [SSH User Authentication](#ssh-user-authentication)
* [Server Options](#server-options)
* [Running Ghidra Server on Microsoft Windows](#running-ghidra-server-on-microsoft-windows)
  * [Server Scripts](#server-scripts-located-within-the-server-subdirectory)
  * [Running Server in Console Window](#running-server-in-console-window-intended-for-diagnostic-use-only)
  * [Install as Automatic Service](#install-as-automatic-service-must-have-administrator-privilege)
  * [Uninstall Service](#uninstall-service-must-have-administrator-privilege)
* [Running Ghidra Server on Linux or macOS](#running-ghidra-server-on-linux-or-macos)
  * [Server Scripts](#server-scripts-located-within-the-server-subdirectory-1)
  * [Running Server in Console Window](#running-server-in-console-window)
  * [Install as Automatic Service](#install-as-automatic-service-must-have-admin-privilege)
  * [Uninstall Service](#uninstall-service-must-have-admin-privilege)
* [Server Administration](#server-administration)
* [Repository Backup](#repository-backup)
* [Clearing Obsolete Checkouts](#clearing-obsolete-checkouts)
* [PKI Certificates](#pki-certificates)
* [Managing PKI Certificate Authorities](#managing-pki-certificate-authorities)
* [Upgrading the Ghidra Server Installation](#upgrading-the-ghidra-server-installation)
* [Troubleshooting / Known Issues](#troubleshooting--known-issues)
  * [Failures Creating Repository Folders / Checking in Files](#failures-creating-repository-folders--checking-in-files)
  * [Client/Server connection errors](#clientserver-connection-errors)
  * [MS Windows - ERROR Incorrect function (WindowsWatchService)](#ms-windows---error-incorrect-function-windowswatchservice)
  * [MS Windows - ERROR Missing Temp Directory](#ms-windows---error-missing-temp-directory)
  * [MS Windows 7 and 8 - ghidraSvr.bat, svrInstall.bat, or svrUninstall.bat Error](#ms-windows-7-and-8---ghidrasvrbat-svrinstallbat-or-svruninstallbat-error)
  * [Linux - SELinux must be disabled](#linux---selinux-must-be-disabled)
  * [Linux - Potential hang from /dev/random depletion](#linux---potential-hang-from-devrandom-depletion)
  * [macOS - Service fails to start](#macos---service-fails-to-start-macos-1014-mojave-and-later)

## Introduction
The Ghidra Server is incorporated into the standard Ghidra software distribution. Simply unpack the 
Ghidra distribution, configure the Ghidra Server and perform the OS-specific install and you should 
have the server running in no time.

The Ghidra Server utilizes the YAJSW Java service wrapper to launch the application and provides OS 
specific scripts which enable the application to run as a service.

__NOTE__: It is very important that only a single server instance is running against any given 
server repositories directory.  This can be assured if only the default port is ever used.  
The daemon/service mechanism assumes that only one instance of the service exists.  Attempting to 
run a second concurrent instance may lead to difficulties and is not supported.

__NOTE__: It is highly recommended that the installation files for Ghidra reside on a local drive 
and that the intended Ghidra Server process owner is granted full access to the Ghidra installation 
directory (this is frequently not the case for NFS/SMB mounted home directories). 

You may also refer to the _GettingStarted.html_ file within the Ghidra installation root directory
for general installation information.

([Back to Top][top])

## Java Runtime Environment
The installation of a suitable Java Runtime Environment must be completed before installing or
running the Ghidra Server.  Please refer to the Getting Started document to identify a suitable 
version.  Since the Ghidra Server is unable to interactively identify a Java installation at runtime
it must rely upon the setting of `JAVA_HOME`, execution search PATH or the use of standard Java 
installation locations.  It is important to consider the service execution environment which may 
differ from the administrator who may be installing the service.  For this reason use of an 
installed Java release may be preferable over one that is simply unpacked to an arbitrary location.

([Back to Top][top])

## Server Configuration
Before installing and running the Ghidra Server, the `server/server.conf` file must be modified to 
suit your particular needs.  Within this file, locate the lines labeled:
```
wrapper.app.parameter.#
```
These lines correspond to a sequential list of server command line arguments - be sure not duplicate 
a parameter number.  The comments within this file indicate the available command line arguments 
which should be specified here based upon the desired user authentication, repositories directory 
location and other associated options.

It is highly recommended that you specify a repositories directory outside of your Ghidra 
installation directory with an absolute path so that it may be re-used more easily with future 
upgraded installations of Ghidra.  Due to the use of a filesystem watcher service the use of a 
locally attached storage device is preferred and will also ensure the best performance.

__NOTE__: The server may fail to start if the repository native filesystem does not support the use 
of a filesystem watcher service.  This could occur if attempting to use a remotely-mounted 
filesystem which may lack the required event support.  The watcher service is used in conjunction 
with command processing associated with the `svrAdmin` command.  If a running server fails to 
process queued `svrAdmin` command requests, the repository native filesystem may be the cause.

When upgrading your Ghidra installation, you will need to copy your app parameters from your old 
_server.conf_ to the new _server.conf_.  Do not copy the entire _server.conf_ file as this may 
prevent the server from running properly.  If running as a service, you must run the 
`server/svrUninstall` script from the old installation before running the `server/svrInstall` script
from the new installation.  Using a non-default repositories directory outside your Ghidra 
installation will simplify the migration process.

([Back to Top][top])

## Server Logs
The Ghidra Server produces two log files, which for the most part have the same content. The service
_wrapper.log_ file generally resides within the Ghidra installation root directory, while the 
_server.log_ file resides within the configured _repositories/_ directory.  When running the server
in console mode all _wrapper.log_ output is directed to the console.

([Back to Top][top])

## Server Memory Considerations
The Ghidra Server currently maintains an in-memory state for all repositories. We are aware that 
this can limit the scalability of the Ghidra Server.  The maximum memory used by the process can be 
set within the `server/server.conf` file by adjusting the following setting:
```
wrapper.java.maxmemory
```
__WARNING__! There are currently no safeguards when insufficient memory is available to the Ghidra 
Server and can cause severe failure if an out of memory error occurs.

The following formula can be used to approximate an appropriate setting for this `maxmemory` value 
where `FileCount` represents the maximum number of repository files and `ClientCount` is the number 
of active Ghidra clients connected at one time.
```
wrapper.java.maxmemory = 16 + (32 * FileCount/10000) + (2 * ClientCount)
```
Example:
```
100,000 files and 25 connected Ghidra clients
16 + (32 * 100000/10000) + (2 * 25) = 386
wrapper.java.maxmemory=772  (2 * 386, see NOTE below)
```
__NOTE__: Due to the dynamic memory demands on the server not considered by this calculation (e.g., 
open file handles, etc.), the actual `maxmemory` setting used should be larger than the calculated 
value.  At a minimum, it is recommended that the calculated value be doubled, and a larger value
may be appropriate based upon server loading.

The Java VisualVM tool (if available for your host) may also be used to examine memory usage while 
the server is running.  This tool is NOT provided with any Ghidra distribution.

([Back to Top][top])

## Note regarding use of DNS (name lookup service)
Both Ghidra Server and client application make extensive use of forward and reverse network name 
lookups.  If this service is not properly configured on your network and hosts, names may fail to 
be resolved or in certain cases cause severe performance delays due to improperly serviced DNS 
name/address queries.

By default the server will attempt to identify an appropriate remote access IPv4 address which will
be written to the log at startup.  In addition, the server will listen for incoming connections on 
all IPv4 interfaces by default.  It is important to understand the difference between the published 
remote access address and the listening address (i.e. interface) which are both configurable.  See 
the `-ip` and `-i` options in the [Server Options](#server-options) section for more details.

([Back to Top][top])

## User Authentication
The Ghidra Server has been designed to support many  possible user authentication modes:
* __No authentication__: Any user which has been added to the server may connect without password or
  credentials.

* __Local Ghidra password (-a0)__: Passwords associated with each user added to the server are 
  maintained in the _users_ file located within the repositories directory. The user will be 
  prompted for this password when connecting to the server.  The default password _changeme_ is used
  when a user is first added or when the user is reset (see 
  [Server Administration](#server-administration)). This default password must be changed by the 
  user to avoid its expiration.

* __Active Directory via Kerberos (-a1)__: User authentication is performed against your local 
  Active Directory system using Kerberos to do so.  The `-d<ad_domain>` argument is required to 
  specify the domain name of your Active Directory system.
  
  It is also possible to authenticate against your Active Directory system using LDAP.  See the LDAP
  example when using JAAS -a4 mode.

* __PKI authentication (-a2)__: User authentication is performed using PKI user certificates. When 
  using this mode, the distinguished name (DN) for each user must be associated with each server 
  User ID (see [Server Administration](#server-administration)). In addition, each user must 
  configure Ghidra with the location of their signing key/certificate keystore file (see 
  [PKI Certificates](#pki-certificates) for more information). 
  
  Please note that each user's certificate must be issued by a trusted certificate authority which
  has been properly added to the Ghidra Server's _cacerts_ file.  See 
  [Managing PKI Certificate Authorities](#managing-pki-certificate-authorities) for more 
  information.
  
  In an attempt to simplify the determination of user DN's, a log file (_UnknownDN.log_) records 
  user DNs which are unknown.  After adding a user to the server, ask the user to attempt a login 
  using their PKCS certificate.  This should result in their DN being recorded to this log file. The
  server administrator may now copy the appropriate DN from this log file when assigning the DN for
  a user.

* __JAAS - Java Authentication and Authorization Service (-a4)__: User authentication is delegated 
  to the JAAS subsystem.  The -jaas `<config_file>` argument is required to specify the JAAS config
  file.  The JAAS config file supplied (_server/jaas.conf_) contains various example configurations 
  which may be used to establish an 'auth' configuration section.  None of the example 
  configurations use the 'auth' name so they will be ignored by default.
	
  JAAS is architected similar to Linux/Unix PAM, where a named authentication configuration is 
  possibly composed of several different modules.  Ghidra's support of JAAS only handles single 
  simple JAAS modules that requests the name and password from the user.

  Some known JAAS login modules:
  * __com.sun.security.auth.module.LdapLoginModule__: Allows authentication to an LDAP server. There
    is an example of using this module to authenticate against an Active Directory system in the
    jaas.conf file.
  
  * __net.sf.jpam.jaas.JpamLoginModule (Linux/Unix server only)__: Allows authentication against
    the local PAM configuration.  You will need to download JPAM from SourceForce and install the
    libraries in the necessary locations.  See the example in the _jaas.conf_ file. 
  
  * __ghidra.server.security.loginmodule.ExternalProgramLoginModule__: Spawns an external program 
    for each authentication request, and uses the external program's exit code as the indicator
    of successful authentication.
	
	There is an example (and non-useful) implementation of an external authenticator provided with
    the Ghidra installation called _server/jaas_external_program.example.sh_.

    This login module strives to be compatible with Apache's mod_authnz_external API, and you should
	be able to use any mod_authnz_external authenticator with Ghidra.

    The external program is fed the username\n and password\n on its STDIN (i.e., two text lines).
    The external authenticator needs to exit with 0 (zero) error level if the authentication was 
	successful, or a non-zero error level if not successful.
		
  * __com.sun.security.auth.module.Krb5LoginModule__: Not recommended. This login module is used in 
    the `-a1` Active Directory via Kerberos authentication mode, and as such you should use it that 
    way.  
		
* __Use of an SSH pre-shared key (-ssh</)__: Supported as an alternate form of authentication when 
  using Local Ghidra password (`-a0`). This SSH authentication is currently supported by the 
  Headless Analyzer only. See [SSH User Authentication](#ssh-user-authentication) for configuration
  details.

([Back to Top][top])

## SSH User Authentication
When the `-ssh` option has been included in conjunction with password based authentications mode 
(`-a0`) a user's SSH public key may be added to the server to facilitate access by a Headless 
Analyzer.  An SSH public key file must be added to the server repository for each user who requires 
headless SSH authentication.  The SSH public key file (e.g., _id_rsa.pub_) must be copied to the 
_repositories/~ssh/_ subdirectory to a file named `<username>.pub`.  Removing the file will 
eliminate SSH based authentication for the corresponding user.  When creating the _~ssh/_ 
subdirectory, it should be owned by the Ghidra Server process owner with full access and any SSH 
public keys readable by the process owner.  Changes to the SSH public key files may be made without 
restarting the Ghidra Server.

Each user may generate a suitable SSH key pair with the `ssh-keygen` command issued from a shell 
prompt.  A PEM formatted RSA key-pair should be generated using the following command options:
```
ssh-keygen -m pem -t rsa -b 2048
```
__NOTE__: Ghidra Server authentication does not currently support the OPENSSH key format which may 
be the default _ssh-keygen_ format (`-m` option) on some systems such as Ubuntu. In addition, other 
key types (`-t` option) such as _ecdsa_ and _ed25519_ are not currently supported.

([Back to Top][top])

## Server Options

### Networking options

#### `-ip <hostname>` 
Identifies the remote access hostname (FQDN) or IPv4 address which should be  used by remote clients
to access the server.  By default the host name reported by the operating system is resolved to an 
IPv4 address, if this fails the local loopback address is used.  The server log will indicate the 
remote access hostname at startup.  This option may be required when a server has multiple IP 
interfaces, relies on a dynamic DNS or other network address translation for incoming connections. 
This option establishes the property value for _java.rmi.server.hostname_.
			
#### `-i <#.#.#.#>`
Forces the server to be bound to a specific IPv4 interface on the server. If specified and the `-ip`
option is not, the address specified by `-i` will establish the remote access IP address as well as 
restrict the listening interface. If this option is not specified connections will be accepted on 
any interface.

#### `-p#`
Allows the base TCP port to be specified (default: 13100).  The server utilizes three (3) TCP ports 
starting with the specified base port (e.g., 13100, 13101 and 13102). The ports utilized are logged
by the server during startup.

#### `-n`
Enables reverse name lookup for IP addresses when logging (requires proper configuration of reverse
lookup by your DNS server).  Please note that logging of host names is now disabled by default due
to the slow-down which occurs when reverse DNS is not properly configured on the  network.
	
### Authentication options

#### `-a#`
Allows a user authentication mode to be specified (see [User Authentication](#user-authentication))

#### `-d<ad_domain>`
Sets the Active Directory domain name. Example: "-dmydomain.com"

#### `-e#`
Allows the reset password expiration to be set to a specified number of days (default is 1-day). A 
value of 0 prevents expiration.
	
#### `-jaas <config_file>`
Specifies the path to the JAAS config file (when using `-a4`), relative to the ghidra/server 
directory (if not absolute).
	
See _jaas.conf_ for examples and suggestions. It is the system administrator's responsibility to
craft their own JAAS configuration directive when using the `-a4` mode.

#### `-u`
Allows the server login user ID to be specified at time of login for `-a0` authentication mode. 
Without this option, the users client-side login ID will be assumed.

#### `-autoProvision`
Enable the auto-creation of new Ghidra Server users when they successfully authenticate to the 
server (`-a1` and `-a4` modes only). Users removed from the authentication provider (e.g., Active 
Directory) will need to be deleted manually from the Ghidra Server using `svrAdmin` command.
	
#### `-anonymous`
Enable anonymous access support for Ghidra Server and its repositories.  Only those repositories
which specifically enable anonymous access will be accessible as read-only to an anonymous user.

#### `-ssh`
Enable SSH as an alternate form of authentication when using `-a0` authentication mode.

([Back to Top][top])

## Running Ghidra Server on Microsoft Windows

### Server Scripts (located within the server subdirectory)
* __svrInstall.bat__: Installs server as service (_ghidraSvr_)
* __svrUninstall.bat__: Removes previously installed server service
* __svrAdmin.bat__: Facilitates Ghidra Server administrative commands (see 
  [Server Administration](#server-administration))
* __ghidraSvr.bat__: Provides a variety of commands for controlling the server when	running as a 
  daemon process.  When running this script it accepts a single argument which is one of the 
  following commands.  Many of these commands are included so that this script may be used for 
  controlling the service.
    * __console__: Starts server within the current terminal window. The _console_ argument may be
	  omitted to allow for double-click execution in this mode.
	* __start__: Starts the previously installed Ghidra Server service
	* __stop__: Stops the installed Ghidra Server service which is currently running
	* __restart__: Stops and restarts the previously installed Ghidra Server service
    * __status__: Displays the current status of the Ghidra Server (_ghidraSvr_) service

__NOTE__: The above scripts may be run from a _CMD_ window, or by double-clicking the script file 
from an Explorer window.  Other than the console and status operation, elevated privilege is needed 
to run these commands.  As such the user executing these scripts must be a member of the 
Administrator group and must be run with elevated privilege.  If using Windows Vista or newer, the 
best way to accomplish this is to run the _CMD_ shell using the _Run as Administrator_ action which 
is available by right-clicking on a command shortcut or batch file.  If the _CMD_ shell is run in 
this manner, the Ghidra Server scripts may then be executed within the shell to run with 
administrator privilege.

### Running Server in Console Window (intended for diagnostic use only)
__NOTE__: Starting the server in console mode is generally intended for diagnostic use only.  
Extreme care must be taken to ensure that any user who starts the Ghidra Server via this script 
has full access to all directories and files within the root repository directory.

If the Ghidra Server is not already running, it may be started within a console window by running 
the `ghidraSvr.bat console` command.  When you wish to terminate the server, use the 
`Ctrl-C` key sequence within the server console window and wait for a clean shutdown.

### Install as Automatic Service (must have Administrator privilege)
The Ghidra Server may be installed as an automatic service by executing the _svrInstall.bat_ script.
This script may be run from a _CMD window, or by double-clicking the script file from an Explorer 
window.  Once installed, the server will start automatically when the system is booted. Immediately 
after running this script the service will not be running, you will need to either reboot or start 
the service from the Service Control Panel.

### Uninstall Service (must have Administrator privilege)
If after installing the Ghidra Server as a service you wish to uninstall it, you may run the 
_svrUninstall.bat_ script.  You must stop the service via the Service Control Panel prior to running
this script.  This script may be run from a _CMD_ window, or by double-clicking the script file from

__NOTE__: It is very important that you uninstall the service prior to doing any of the following 
activities:
* Deleting or upgrading the Ghidra installation
* Moving/renaming the Ghidra installation directory

([Back to Top][top])

## Running Ghidra Server on Linux or macOS

__NOTE__: macOS has limited support (see 
[macOS - Service fails to start](#macos---service-fails-to-start-macos-1014-mojave-and-later)).

### Server Scripts (located within the server subdirectory)
* __svrInstall__: Installs server as service (_ghidraSvr_ or _wrapper.ghidraSvr_)
* __svrUninstall__: Removes previously installed server service
* __svrAdmin__: Facilitates Ghidra Server administrative commands (see 
  [Server Administration](#server-administration))
* __ghidraSvr__: Provides a variety of commands for controlling the server when	running as a 
  daemon process.  When running this script it accepts a single argument which is one of the 
  following commands.  Many of these commands are included so that this script may be used for 
  controlling the service.
    * __console__: Starts server within the current terminal window
	* __start__: Starts the previously installed Ghidra Server service
	* __stop__: Stops the installed Ghidra Server service which is currently running
	* __restart__: Stops and restarts the previously installed Ghidra Server service
    * __status__: Displays the current status of the Ghidra Server (_ghidraSvr_) service

### Running Server in Console Window
__NOTE__: Starting the server in console mode is generally intended for diagnostic use only. Care 
must be taken to ensure that any user who starts the Ghidra Server via this script  has full access 
to all directories and files within the root repository directory.

If the Ghidra Server is not already running, it may be started within a terminal window by running 
the command: `ghidraSvr console`.  When you wish to terminate the server, use the `Ctrl-C` key 
sequence within the server console window and wait for a clean shutdown.

### Install as Automatic Service (must have admin privilege)
The Ghidra Server may be installed as an automatic service by executing the _svrInstall_ script. 
Once installed, the server will start automatically when the system is booted.  If performing an 
upgrade to an existing Ghidra Server installation you must uninstall the existing Ghidra Server
first (see [Uninstall Service](#uninstall-service-must-have-admin-privilege)).

In order for the installed service script to survive Java system updates, which may change the 
installed Java version, it is highly recommended that the `GHIDRA_JAVA_HOME` variable be set
properly at the top of the `ghidraSvr` script prior to the server install. `GHIDRA_JAVA_HOME` should
refer to a non-changing path where Java is installed.  For a system-installed Java the major-version
symblic-link path should be specified in favor of a full-version path which stipulates minor-version
information.  In addition, it is important that the Ghidra Server service be restarted anytime the 
installed Java version is updated where this symbolic link has been modified to reference a newly 
installed Java version.  Failure to use this approach may result in the Ghidra Server service script
referring to an invalid Java path following an update.

Example setting of `GHIDRA_JAVA_HOME` within _ghidraSvr_ script:
```
GHIDRA_JAVA_HOME=/usr/lib/jvm/java-21-openjdk
```
If it is preferred to run the service with a dedicated local user account, the following entry may 
be added to the _server.conf_ file with the appropriate account specified in place of `<uid>`.
A dedicated local service account should generally be a no-login account with a corresponding group 
identifier with the same name (i.e., see _/etc/passwd_ and _/etc/group_). The local account should 
be established and specified with server.conf prior to	installation of the Ghidra Server service. 
```
wrapper.app.account=<uid>
```
It is also important that the repositories directory and Ghidra installation files be owned by the 
service account with proper permissions.  Note that while the Ghidra Server Java process will run 
using the specified _uid_, the _wrapper_ process will continue to run as _root_ and monitor/manage 
the Java process.

### Uninstall Service (must have admin privilege)
If after installing the Ghidra Server as a service you wish to uninstall it, you may run the 
_svrUninstall_ script.

__IMPORTANT__: It is very important that you uninstall the Ghidra Server service using the original 
Ghidra software installation.  Use of a newer Ghidra software install may not properly uninstall a 
different service version.  This is particularly true if uninstalling a Ghidra Server version prior 
to 11.2.  Such an uninstall will be required when:
* deleting or upgrading the Ghidra installation
* moving/renaming the Ghidra installation directory

__NOTE__: The service control mechanism for Linux changed with the Ghidra 11.2 release. The 
_init.d_ mechanism was previously used in all cases, whereas the _systemd_ service mechanism may now
used based upon YAJSW preference.  

([Back to Top][top])

## Server Administration
The script _svrAdmin_, or _svrAdmin.bat_, provides the ability to manage Ghidra Server users and 
repositories.  This script must be run from a command shell so that the proper command line 
arguments may be specified.  This command should only be used after the corresponding Ghidra 
installation has been properly configured via modification of the _server/server.conf_ file
(see [Server Configuration](#server-configuration)) and installed and/or started.  

Many of the commands are queued for subsequent execution by the Ghidra Server process. Due to this 
queuing, there may be a delay between the invocation of a _svrAdmin_ command and its desired affect. 
The Ghidra log file(s) may be examined for feedback on queued command execution (see 
[Server Logs](#server-logs)).

The general command usage is:
```bash
svrAdmin [<server-root-path>]
         [-add <user_sid> [--p]]
         [-grant <user_sid> <"+r"|"+w"|"+a"> <repository_name>] 
         [-revoke <user_sid> <repository_name>] 
         [-remove <user_sid>] 
         [-reset <user_sid> [--p]] 
         [-dn <user_sid> "<user_dn>"]
         [-list  <user_sid> [<user_sid>...]]
         [-list [--users]]
         [-users]
         [-migrate-all]
         [-migrate "<repository_name>"]
```

#### `<server-root-path>`
There is normally no need to specify this argument on the command line.The default server-root-path 
is determined by the _server.conf_ setting of the `ghidra.repositories.dir` variable.  This allows 
both the server execution and _svrAdmin_ script to utilize the same setting.

#### `-add` (Adding a User)
All authentication modes require that a user first be added to the server for a connection to be 
permitted.  If Ghidra password authentication is used (`-a0`), the initial password is set to 
"__changeme__". This password must be changed by the user within 24-hours to avoid its expiration 
(password expiration period can be extended as a server option, see `-e` 
[server option](#server-options).  Alternatively, the initial password may be specified by including
the optional `--p` parameter which will prompt for an initial password.

Examples:
```bash
svrAdmin -add mySID
svrAdmin -add mySID --p
```

#### `-grant` (Grant Repository Access for User)
Grant access for a specified user and repository where both must be known to the server. Repository
access permission must be specified as +r for READ_ONLY, +w for WRITE or +a for ADMIN.

Examples:
```bash
svrAdmin -grant mySID +a myRepo
svrAdmin -grant mySID +w myRepo
```
    
#### `-revoke` (Revoke Repository Access for User)
Revoke the access for a specified user and named repository.  Currently, revoking access for a user 
does not disconnect them if currently connected.

Examples:
```bash
svrAdmin -revoke mySID myRepo
```

#### `-remove` (Removing a User)
A user may be removed from the Ghidra Server and all repositories with this command form.  This will
only prevent the specified user from connecting to the server in the future and will have no effect 
on the state or history of repository files.  If a repository admin wishes to clear a user's 
checkouts, this is a separate task which may be performed from an admin's Ghidra client.  Currently,
removing a user does not disconnect them if currently connected.

Example:
```bash
svrAdmin -remove mySID
```

#### `-reset` (Reset User's Ghidra Password)
If a user's password has expired, or has simply been forgotten, the password may be reset to 
"__changeme__".  After resetting, this password must be changed by the user within 24-hours to avoid
its expiration (password expiration period can be extended as a server option). Alternatively, the 
new password may be specified by including the optional `--p` parameter which will prompt for an 
initial password.

Example:
```bash
svrAdmin -reset mySID
svrAdmin -reset mySID --p
```
    
#### `-dn` (Assign User's Distinguished Name)
The use of PKI authentication requires that each user's DN be associated with their user SID.

Example:
```bash
svrAdmin -dn mySID "CN=MyName,OU=AGENCY,OU=DoD,O=U.S. Government,C=US"
```
__NOTE__: After having been added to the server, a user's DN may be copied from the _UnknownDN.log_
file following an attempted connection with their PKCS certificate.
    
#### `-list` (List All Repositories and/or User Permissions)
If the `--users` option is also present, the complete user access list will be included for each 
repository. Otherwise, command may be followed by one or user SIDs (separated by a space) which will
limit the displayed repository list and access permissions to those users specified.

Example:
```bash
svrAdmin -list
svrAdmin -list --users
svrAdmin -list mySID
```

#### `-users` (List All Users)
Lists all users with server access.

Example:
```bash
svrAdmin -users
```
    
#### `-migrate-all` (Migrate All Repositories to Use Indexed File-System Storage)
For all repositories which are using the deprecated Mangled Filesystem storage, they will be 
marked for migration to the Indexed Filesystem storage with support for longer file pathnames.  
The actual migration will be performed when the Ghidra Server is restarted.

Please note that any migration to the Indexed filesystem storage is a one-way conversion so a 
backup of your server repositories directory is highly recommended before proceeding.

Example:
```bash
svrAdmin -migrate-all
```
    
#### `-migrate` (Migrate a Specified Repository to use Indexed File-System Storage)
The specified repository will be marked for migration to the Indexed Filesystem storage with support
for longer file pathnames.  The actual migration will be performed when the Ghidra Server is 
restarted.

Please note that any migration to the Indexed filesystem storage is a one-way conversion so a backup
of your server repositories directory is highly recommended before proceeding.

Example:
```bash
svrAdmin -migrate "myProject"
```

([Back to Top][top])

## Repository Backup
As with any server, it is highly recommended that your server repositories directory be periodically 
backed-up or whenever an upgrade (or data migration) is performed.  While backups may be taken while 
the Ghidra Server is idle (e.g., after midnight), it is always safest to stop the Ghidra Server 
while a backup is in progress.

([Back to Top][top])

## Clearing Obsolete Checkouts
Any user who has Admin privilege of a specific repository may use the Ghidra client to View 
Checkouts for a specific file and Delete individual checkouts from those that are listed.  The 
_View Checkouts_ action is available from the popup-menu of the Ghidra Project Window by 
right-clicking on a specific project file.

Under special circumstances (e.g., classroom environment) it may be desirable to remove all 
checkouts either for a specific repository or an entire Ghidra Server.  Under Linux/Mac this is 
most easily accomplished from the command shell while the Ghidra Server is stopped.  The following 
command may be used:

```bash
find <repo-path> -name checkout.dat -exec rm {} \;
```
	
where `<repo-path>` is the directory path of a specific named repository root, or the parent 
repositories directory if clearing checkouts for all repositories.

__WARNING!__ Since the `find` command is recursive, care must be taken when specifying the 
`<repo-path>` and the other parameters.  If you specify the incorrect `<repo-path>` or omit the 
correct `-name` argument, you may remove important files without the ability to recover.

([Back to Top][top])

## PKI Certificates
PKI keys/certificates can be used to authenticate clients and/or servers. When using the Ghidra 
Server PKI authentication mode this corresponds to "client authentication" which requires the 
_server.conf_ to specify a _cacerts_ file location and each user client to configure a user signing
key/certificate keystore file.  If clients wish to authenticate the server, the _server.conf_ must 
specify a server key/certificate keystore file and each user client must configure a _cacerts_ file.
See [Managing PKI Certificate Authorities](#managing-pki-certificate-authorities) for more 
information on configuring a _cacerts_ file.

User and server certificates must be acquired through one of many trusted authorities identified by 
the _cacerts_ file installed by the peer system.  Your network support staff should be able to help
you acquire a suitable signing key/certificate in the form of either a _*.p12_, _*.pks_, or _*.pfx_ 
file.

User's of the Ghidra GUI application can install their key/certificate file via the project window 
menu item _Edit->Set PKI Certificate..._. The user will be prompted for their keystore password the 
first time key access is required for a network connection after starting the application. If using
the _analyzeHeadless_ script, see the _analyzeHeadlessREADME.html_ file for details.

If the Ghidra Server will be installing a server certificate, the _server.conf_ file should be 
modified to properly identify the server's key/certificate location (_ghidra.keystore_) and password
(_ghidra.password_).

([Back to Top][top])

## Managing PKI Certificate Authorities
When utilizing PKI authentication for a Ghidra Server a set of certificates for trusted Certificate 
Authorities (CA) must be collected and added to a cacerts keystore file created using the Java 
keytool.  The Java keytool can be found within the Java Development Kit (JDK) provided with 
Ghidra (_java/bin/keytool_) or any other Java distribution.  The default cacerts keystore file 
location is _Ghidra/cacerts_ and is also specified by the _ghidra.cacerts_ property setting within 
the _server.conf_ file.  Uncomment this specification within the _server.conf_ file to activate use
of the _cacerts_ for all incoming SSL/TLS connections (i.e., all Ghidra client users must install 
and employ the use of their personal PKI signing certificate for both headed and headless use - see 
[PKI Certificates](#pki-certificates)).  Clients can also impose server authentication for all HTTPS
and Ghidra Server connections by creating the _cacerts_ file and enabling the _ghidra.cacerts_ 
property setting within the _support/launch.sh_ and/or _support/launch.bat_ scripts.

Individual CA public key certificates should be obtained in a Base64 encoding (see sample below). 
If pasting the encoded certificate into a file, be sure to include an extra blank line after the 
`END CERTIFICATE` line.

Sample Base64 encoded certificate:
```
-----BEGIN CERTIFICATE-----
laSKCIElkjsudCUDusjSUkjeMSUjAJHDuLQWMCMausALkKXMXOOjSKSUjssjSKAA
ksDSDjLKJHAuemCXXUmxxqjaskuDSYRmxiqgDlakkUSUdhemjASKUakjhuEhxMSD
...
ksJKDwocQwyeEIcbzHtyrSLfoeyGCmvbNLGHpgoruSTYQafzDFTgwjkJHCXVDjdg
KDowiyYTXkcuiwCJXuyqCHpdoORriwwcCWUskucuwHDJskuejdkUWJCUDSjujsUE
-----END CERTIFICATE-----
```
You can inspect the contents of a Base64 encoded certificate file with the following command:

```bash
keytool -printcert -v -file <base64file>
```
where:
* `<base64file>` is the file containing the Base64 encoded CA certificate to be imported.

The Owner common name (CN) displayed by this command should be used as the alias when importing the 
certificate into your cacerts file.

The following command should be used to add a CA certificate to a new or existing cacerts file:

```bash
    keytool -import -alias "<caAlias>" -file <base64file> -storetype jks -keystore <cacerts-file>
```
where:
* `<caAlias>` is the name of the CA corresponding to the imported certificate.
* `<base64file>` is the file containing the Base64 encoded CA certificate to be imported.
* `<cacerts-file>` is the cacerts file to be used by the Ghidra Server (and/or client if needed).
    
The keystore password will be requested and is used to restrict future modifications to the 
_cacerts_ file.

When starting the Ghidra Server with PKI authentication enabled, the CA certificates contained 
within the _cacerts_ file will be dumped to the log with their expiration dates.

Please note that the Ghidra Server does not currently support Certificate Revocation Lists (CRLs).

([Back to Top][top])

## Upgrading the Ghidra Server Installation
1. Be sure to backup your projects and tools to ensure that the new Ghidra installation does not 
   overwrite any of your data. Individual program files upgraded to a newer version of Ghidra 
   can not be opened with an older version.

2. Uninstall an installed Ghidra Server Service by following the _Uninstall Service_ instructions 
   corresponding to your operating system 
   ([Windows](#uninstall-service-must-have-administrator-privilege) or 
   [Linux/macOS](#uninstall-service-must-have-admin-privilege)).
    
3. Unzip the new Ghidra distribution to a new installation directory (general unpacking and 
   installation guidelines may be found in _ghidra_x.x/GettingStarted.html_).

4. Copy the old _repositories_ directory to the new Ghidra Server installation directory.

5. Copy the `wrapper.app.parameter.#` lines from your old _server/server.conf_ file to the new 
   installation _server/server.conf_.  For 5.0 release and earlier, your old _server.conf_ file is
   located within a platform-specific directory (`core/os/<platform>`). No other changes should be 
   made to your new _server.conf_ file.

   __Do not replace the new server.conf file with your old server.conf file, as this could cause 
   server problems.__

6. If desired, install the Ghidra Server Service from the new installation server subdirectory by 
   following the instructions corresponding to your operating system 
   ([Windows](#install-as-automatic-service-must-have-administrator-privilege) or 
   [Linux/macOS](#install-as-automatic-service-must-have-admin-privilege)).

__WARNING!__ __As of Ghidra 7.0 a new project/server storage implementation, `Indexed-V1`, has been 
added which is not compatible with older versions of Ghidra.__  The _Indexed-V0_ filesystem storage 
allows longer filenames and paths to exist within a project, while the `V1` version expands support 
to facilitate some of the very large project/repository features introduced in Ghidra 7.0. Since the 
legacy storage implementation (_Mangled_) used by older projects and repositories is still 
supported, conflicting storage behavior may exist between a Ghidra project and its server repository
for long filename/path support. It is highly recommended that all server repositories and associated
projects be migrated to the new Indexed storage implementation in a coordinated fashion after making
a complete backup. All new Ghidra projects will utilize the new Indexed storage implementation, so 
care should taken when creating shared projects with older repositories.

__NOTE__: If using Ghidra 6.0.x, opening a project which uses the newer _Indexed-V1_ filesystem may
cause the project storage to revert to the older _Indexed-V0_ filesystem.

A user may determine which storage implementation is used by a project by viewing the _Project Info_
display (via _Project -> View Project Info..._). Local projects using the legacy _Mangled_ 
filesystem may be migrated to the new _Indexed_ filesystem via this _Project Info_ panel. The status
of Ghidra Server repositories storage can be determined and flagged for migration via the 
_server/svrAdmin_ script (described in the [Server Administration](#server-administration) section).
Please note that any migration to the _Indexed_ filesystem storage is a one-way conversion so a 
backup of your project or server repositories directory is highly recommended before proceeding.

([Back to Top][top])

## Troubleshooting / Known Issues

### Failures Creating Repository Folders / Checking in Files
If you see continuous failures to create repository folders or failures to check in files, check 
the disk space on the server or folder permissions. When the server runs out of disk space, it 
cannot create folders or check in files.

### Client/Server connection errors
The Ghidra Server has transitioned to using SSL/TLS connections when accessing the server's RMI
registry.  This change in communication protocol can cause unexpected symptoms when attempting to
connect incompatible versions of Ghidra.  When an older incompatible Ghidra client attempts to access a 
newer SSL/TLS enabled Ghidra Server registry, the following connection error will occur:
```
non-JRMP server at remote endpoint
```

### MS Windows - ERROR Incorrect function (WindowsWatchService)
The Ghidra Server employs a file system watcher service for the repositories directory which must 
reside within a locally mounted NTFS or ReFS filesystem.

### MS Windows - ERROR Missing Temp Directory
Running the Ghidra Server as an installed service under Windows may attempt to use a non-existing 
temporary directory (e.g., `C:\Windows\system32\config\systemprofile\AppData\Local\Temp\`). The 
work-around for this is to configure the server to use an existing temporary directory (e.g., 
`C:\Windows\Temp`).  This can be done by editing the _server.conf_ file, locate the 
_wrapper.java.additional_ entries and add/uncomment an entry with your temporary directory 
specified. For example:
```
wrapper.java.additional.3=-Djava.io.tmpdir=C:\Windows\Temp
```
Be sure to use the next unique sequence number for your _wrapper.java.additional_ entry.

### MS Windows 7 and 8 - ghidraSvr.bat, svrInstall.bat, or svrUninstall.bat Error
The following error may occur when attempting to install/uninstall/start/stop/restart the Ghidra 
Server under MS Windows 7 or 8 even if the user is a member of the Administrator group:
```
Access denied: please check the user credentials
```
The user executing these scripts must be a member of the Administrator group and must be run with 
elevated privilege.  The best way to accomplish this is to run the _CMD_ shell using the 
_Run as Administrator_ action which is available by right-clicking on a command shortcut or batch 
file.  If the _CMD_ shell is run in this manner, the Ghidra Server scripts may then be executed 
within the shell to run with administrator privilege.  Failure to run the scripts in this manner may
cause failure information to be hidden from view due to the privilege escalation mechanism.

### Linux - SELinux must be disabled
The Ghidra Server may not start properly if SELinux has not been disabled.  This setting is 
specified in the file _/etc/selinux/config_.

### Linux - Potential hang from /dev/random depletion
SSL communications and the PKI/SSH authentication mechanisms employed by GHIDRA make use of the Java
`SecureRandom ` class to generate random numbers required by various cryptographic techniques. On 
Linux systems this class makes use of _/dev/random_ to produce these random numbers which in turn
relies on other system entropy sources to feed it.  We have seen that _/dev/random_ can become 
depleted which can cause the dependent Java application to hang.  While Java claims to have settings
which should allow _/dev/urandom_ to be used, these security settings do not appear to work as 
intended.  The best workaround we have found for systems which exhibit this problem is to install 
_haveged_ (HArdware Volatile Entropy Gathering and Expansion Daemon) which will satisfy the entropy 
demand needed by _/dev/random_.

### macOS - Service fails to start (macOS 10.14 Mojave and later)
The installed service may fail to start with macOS Mojave (10.14) and later due to changes in the 
macOS system protection feature.  When the service fails to start it does not provide any error or 
logging to help determine the cause.  Although granting _Full Disk Access_ to _Java_ can be a 
workaround, this is rather drastic and is not considered desirable since it will allow any Java 
application to run as root.  For this reason, installation of the Ghidra Server as a service on
macOS is discouraged.

([Back to Top][top])

[top]: #ghidra-server-readme