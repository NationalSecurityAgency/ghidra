# BSim Databases from the Command Line 

The ``bsim`` command-line utility, located in the ``support`` directory of a Ghidra distribution, is used to create, populate, and manage BSim databases.
It works for all BSim database backends.
This utility offers a number of commands, many of which have several options.
In this section, we cover only a small subset of the possibilities.  

Running ``bsim`` with no arguments will print a detailed usage message.
   
## Generating Signature Files

The first step is to create signature files from the binaries in the Ghidra project.
Signature files are XML files which contain the BSim signatures and metadata needed by the BSim server.

**Important**: It's simplest to exit Ghidra before performing the next steps, because:
- The H2-backed database can only be accessed by one process at a time.
- In case you have the ``postgres_object_files`` project open in Ghidra, signature generation will fail.
  Non-shared projects are locked when open, and the lock will prevent the signature-generating process from accessing the project.

To generate the signature files, execute the following commands in a shell (adjust as necessary for Windows).

```bash
cd <ghidra_install_dir>/support
mkdir ~/bsim_sigs
./bsim generatesigs ghidra:/<ghidra_project_dir>/postgres_object_files --bsim file:/<database_dir>/example ~/bsim_sigs
```

-  The ``ghidra:/`` argument is the local project which holds the analyzed binaries.
Note that there is only one forward slash in the URL for a local project.
-  The ``--bsim`` argument is the URL of the BSim database.
This command does not add any signatures to the database, but it does query the database for its settings.

## Committing Signature Files

Now, we commit the signatures to the BSim database with the following command (still in the ``support`` directory).

```bash
./bsim commitsigs file:/<database_dir>/example ~/bsim_sigs 
```

Once the signatures have been committed, start Ghidra again.

## Aside: Creating a Database

We continue to use the database ``example``, so this step isn't necessary for the exercises.

However, if we hadn't created ``example`` using ``CreateH2BSimDatabaseScript.java``, we could have used the following command:

```bash
./bsim createdatabase file:/<database_dir>/example medium_nosize
```
- ``medium_nosize`` is a database template. 
    - "medium" (vs. "large") affects the vector index and is not relevant to H2 databases.  
    - "nosize" means that size differences for varnodes of size four bytes and above are not incorporated into the BSim features.
    This is necessary to allow matching between 32-bit and 64-bit code.
- The ``createdatabase`` command can also be used to create a BSim database on a PostgreSQL or Elasticsearch server, provided the servers are configured and running. 
See the "BSim" entry in the Ghidra help for details.

## Aside: Executable Categories and Function Tags

It's worth a brief note about Executable Categories and Function Tags, although they are not used in any of the following exercises.

A BSim database can record user-defined metadata about an executable (executable categories) or about a function (function tags).
Categories and tags can then be used as filter elements in a BSim query.
For example, you could restrict a BSim query to search only in executables of the category "OPEN_SOURCE" or to functions which have been tagged "COMPRESSION_FUNCTIONS".  

Executable categories in BSim are implemented using *program properties*, and function tags in BSim correspond to function tags in Ghidra. Properties and tags both have uses in Ghidra which are independent of BSim.
So, if we want a BSim database to record a particular category or tag, we must indicate that explicitly.

For example, to inform the database that we wish to record the ORIGIN category, you would execute the command

```bash
./bsim addexecategory file:/<database_dir>/example ORIGIN
```

Executable categories can be added to a program using the script ``SetExecutableCategoryScript.java``.

Next Section: [Evaluating Matches and Applying Information](BSimTutorial_Evaluating_Matches.md)
