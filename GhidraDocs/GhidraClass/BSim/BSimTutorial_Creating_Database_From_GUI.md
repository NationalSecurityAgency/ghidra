# Creating and Populating a BSim Database from the Ghidra GUI 

This section explains how to create and populate an H2-backed BSim database from the Ghidra GUI. 

## Creating the Database

To create a BSim database, first create a directory on your file system to contain the database.

Next, perform the following steps from the Ghidra Code Browser:

1.  Run the Ghidra script ``CreateH2BSimDatabaseScript.java``.
1.  In the resulting dialog:
    1. Enter "example" in the **Database Name** field. 
    1. Select the new directory in the **Database Directory** field.
    1. Don't change any of the other fields.  
1.  Click **OK**.

## Populating the Database

We now populate the database with an executable which is contained in the Ghidra distribution.

1. Import and analyze the executable ``<ghidra_install_dir>/GPL/DemanglerGnu/os/linux_x86_64/demangler_gnu_v2_41`` using the default analysis options.
1. Run the Ghidra script ``AddProgramToH2BSimDatabaseScript.java`` on this program.
    - The script will ask you to select an H2 database file.  Use ``example.mv.db`` in the database directory.
1. In general you can run this script on other programs to add their signatures to this database, but that's not necessary for the exercises in the next section.

Next Section: [Basic BSim Queries](BSimTutorial_Basic_Queries.md)

