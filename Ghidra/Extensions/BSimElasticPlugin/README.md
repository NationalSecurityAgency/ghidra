# BSimElasticPlugin

## Installation of the Elasticsearch BSim Plug-in
In order to use Elasticsearch as the back-end database for a BSim instance, the lsh plug-in, 
included with this Ghidra extension, must be installed on the Elasticsearch cluster.

The lsh plug-in is bundled in the standard plug-in format as the file `lsh.zip`. It must be 
installed separately on EVERY node of the cluster, and each node must be restarted after the install
in order for the plug-in to become active.

For a single node, installation is accomplished with the command-line `elasticsearch-plugin` script
that comes with the standard Elasticsearch distribution. It expects a URL pointing to the plug-in to
be installed. The basic command, executed in the Elasticsearch installation directory for the node,
is: 
```
bin/elasticsearch-plugin install file:///path/to/ghidra/Ghidra/Extensions/BSimElasticPlugin/data/lsh.zip
```

Replace the initial portion of the absolute path in the URL to point to your particular Ghidra 
installation.

## Deployment
Follow the Elasticsearch documentation to do any additional configuration, starting, stopping, and 
management of your Elasticsearch cluster.

To try BSim with a toy deployment, you can start a single node (as per the documentation) from the 
command-line by just running
```
bin/elasticsearch
```

This will dump logging messages to the console, and you should see `[lsh]` listed among the loaded 
plug-ins as the node starts up.

This will typically start the database with password authentication enabled.  An `elastic` user will
be automatically created with a randomly generated password that gets printed to the console the 
first time the node is started.  To add additional users, use a curl command like
```
curl -k -u elastic:XXXXXX -X POST "https://localhost:9200/_security/user/ghidrauser?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "changeme",
  "roles" : [ "superuser" ],
  "full_name" : "Ghidra User",
  "email" : "ghidrauser@example.com"
}
```

Replace `XXXXXX` with the generated password for the `elastic` user.  This example creates a user 
`ghidrauser`, with administrator privileges. The built-in role `viewer` can be used to create users
with read-only access to the database.

Once the Elasticsearch node(s) are running, whether they are a toy or a full deployment, you can 
immediately proceed to the BSim `bsim` command. The Ghidra/BSim client and `bsim` command 
automatically assume an Elasticsearch server when they see the __https__ protocol in the provided 
URLs, although the __elastic__ protocol may also be specified and is equivalent. The use of the 
__http__ protocol for Elasticsearch is not supported. Adjust the hostname, port number, and 
repository name as appropriate. Use a command-line similar to the following to create a BSim 
instance:
```
bsim createdatabase elastic://1.2.3.4:9200/repo medium_32
```

This is equivalent to:
```
bsim createdatabase https://1.2.3.4:9200/repo medium_32
```

Use a command-line like this to generate and commit signatures from a Ghidra Server repository to 
the Elasticsearch database created above:
```
bsim generatesigs ghidra://1.2.3.4/repo --bsim elastic://1.2.3.4:9200/repo
```

Within Ghidra's BSim client, enter the same URL into the database connection panel in order to place
queries to your Elasticsearch deployment. See the BSim documentation included with Ghidra for full
details.

## Version

The current BSim plug-in was tested with Elasticsearch version `8.8.1`. A change to the 
Elasticsearch scripting interface, starting with version `7.15`, makes the BSim plug-in incompatible
with previous versions, but the lsh plug-in jars may work without change across later Elasticsearch 
versions.

Elasticsearch plug-ins explicitly encode the version of Elasticsearch they work with, and the
plug-in script will refuse to install the lsh plug-in if its version does not match your
particular installation. If your Elasticsearch version is slightly different, you can try
unpacking the zip file, changing the version number to match your software, and then repacking
the zip file. Within the zip archive, the version number is stored in a configuration file
```
elasticsearch/plugin-descriptor.properties
```

The file format is fairly simple: edit the line
```
elasticsearch.version=8.8.1
```

The plugin may work with other nearby versions, but proceed at your own risk.
