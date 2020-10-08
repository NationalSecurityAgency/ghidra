/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.pdb;

import static org.junit.Assert.*;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import org.junit.*;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.bin.format.pdb.PdbParser.PdbFileType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class PdbParserTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramBuilder builder;

	private static String notepadGUID = "36cfd5f9-888c-4483-b522-b9db242d8478";

	// Note: this is in hex. Code should translate it to decimal when creating GUID/Age folder name
	private static String notepadAge = "21";

	// Name of subfolder that stores the actual PDB file
	private static String guidAgeCombo = "36CFD5F9888C4483B522B9DB242D847833";
	private String programBasename = "notepad";

	private File tempDir, fileLocation;
	private Program testProgram;
	//private static String guidAgeCombo = PdbParserNEW.getGuidAgeString(notepadGUID, notepadAge);

	// Bogus symbol repository directory or null directory should not break anything
	private static final File noSuchSymbolsRepoDir = null;

	private String pdbFilename, pdbXmlFilename;
	private String exeFolderName = "exe", pdbXmlFolderName = "pdb_xml",
			symbolsFolderName = "symbols";

	private File pdbFile = null, pdbXmlFile = null, pdbXmlDir = null, symbolsFolder = null;

	private List<File> createdFiles;

	enum PdbLocation {
		NONE, SYMBOLS_SUBDIR, SYMBOLS_NO_SUBDIR, SAME_AS_EXE_SUBDIR, SAME_AS_EXE_NO_SUBDIR
	}

	enum PdbXmlLocation {
		NONE, SAME_AS_PDB, OWN_DIR
	}

	TestFunction[] programFunctions =
		new TestFunction[] { new TestFunction("function1", "0x110", "0x35") };

	public PdbParserTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		// Get temp directory in which to store files
		String tempDirPath = getTestDirectoryPath();
		tempDir = new File(tempDirPath);

		fileLocation = new File(tempDir, exeFolderName);

		testProgram = buildProgram(fileLocation.getAbsolutePath());

		pdbFilename = programBasename + ".pdb";
		pdbXmlFilename = pdbFilename + PdbFileType.XML.toString();

		createdFiles = null;
	}

	@After
	public void tearDown() throws Exception {

		if (fileLocation != null) {
			FileUtilities.deleteDir(fileLocation);
		}
		if (createdFiles != null) {
			deleteCreatedFiles(createdFiles);
		}

		System.gc();
	}

	private Program buildProgram(String exeLocation) throws Exception {

		Program currentTestProgram;

		builder = new ProgramBuilder(programBasename + ".exe", ProgramBuilder._TOY);

		builder.createMemory("test", "0x100", 0x500);
		builder.setBytes("0x110",
			"21 00 01 66 8c 25 28 21 00 01 66 8c 2d 24 21 00 01 9c 8f 05 58 21 00 01 8b 45 00 a3 " +
				"4c 21 00 01 8b 45 04 a3 50 21 00 01 8d 45 08 a3 5c 21 00 01 8b 85 e0 fc ff ff " +
				"c7 05 98 20 00 01 01 00 01 00 a1 50 21 00 01 a3 54 20 00 01 c7 05 48 20 00 01 " +
				"09 04 00 c0 c7 05 4c 20 00 01 01 00 00 00 a1 0c 20 00 01 89 85 d8 fc ff ff a1 " +
				"10 20 00 01 89 85 dc fc ff ff 6a 00 ff 15 28 10 00 01 68 d4 11 00 01 ff 15 38 " +
				"10 00 01 68 09 04 00 c0 ff 15 08 10 00 01 50 ff 15 0c 10 00 01 c3 cc cc cc cc cc");

		currentTestProgram = builder.getProgram();
		currentTestProgram.startTransaction("TEST_" + programBasename + ".exe");

		Options optionsList = currentTestProgram.getOptions(Program.PROGRAM_INFO);
		optionsList.setString(PdbParserConstants.PDB_GUID, notepadGUID);
		optionsList.setString(PdbParserConstants.PDB_AGE, notepadAge);
		optionsList.setString(PdbParserConstants.PDB_FILE, programBasename + ".pdb");
		optionsList.setString("Executable Location",
			exeLocation + File.separator + builder.getProgram().getName());

		return currentTestProgram;
	}

	private List<File> createFiles(PdbLocation pdbLoc, PdbXmlLocation pdbXmlLoc) {

		pdbFile = null;
		pdbXmlFile = null;

		pdbXmlDir = new File(tempDir, pdbXmlFolderName);

		List<File> filesCreated = new ArrayList<>();

		createDirectory(fileLocation);
		filesCreated.add(fileLocation);

		File subDir, subSubDir;

		switch (pdbLoc) {
			// Put PDB file in the /symbols/ folder with subdirectories that
			// include the PDB name and GUID. I.e., the full path to the PDB is:
			//   <temp>/symbols/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/notepad.pdb
			case SYMBOLS_SUBDIR:
				symbolsFolder = new File(tempDir, symbolsFolderName);
				createDirectory(symbolsFolder);
				filesCreated.add(symbolsFolder);

				subDir = new File(symbolsFolder, pdbFilename);
				createDirectory(subDir);
				filesCreated.add(subDir);

				subSubDir = new File(subDir, guidAgeCombo);
				createDirectory(subSubDir);
				filesCreated.add(subSubDir);

				pdbFile = new File(subSubDir, pdbFilename);
				break;

			// Put the PDB file directly into the /symbols folder.
			// I.e., <temp>/symbols/notepad.pdb
			case SYMBOLS_NO_SUBDIR:
				symbolsFolder = new File(tempDir, symbolsFolderName);
				createDirectory(symbolsFolder);
				filesCreated.add(symbolsFolder);

				pdbFile = new File(symbolsFolder, pdbFilename);
				break;

			// Put the PDB file in the same folder as the binary with subdirectories that
			// include the PDB name and GUID.
			// I.e., <temp>/exe/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/notepad.pdb
			case SAME_AS_EXE_SUBDIR:
				subDir = new File(fileLocation, pdbFilename);
				createDirectory(subDir);
				filesCreated.add(subDir);

				subSubDir = new File(subDir, guidAgeCombo);
				createDirectory(subSubDir);
				filesCreated.add(subSubDir);

				pdbFile = new File(subSubDir, pdbFilename);
				break;

			// Put the PDB file in the same folder as the binary
			// I.e., <temp>/exe/notepad.pdb
			case SAME_AS_EXE_NO_SUBDIR:
				pdbFile = new File(fileLocation, pdbFilename);
				break;

			case NONE:
				// Do nothing
				break;

			default:
				fail("Unrecognized pdbLocation choice: " + pdbLoc);
		}

		if (pdbFile != null) {
			createFile(pdbFile);
			filesCreated.add(pdbFile);
		}

		switch (pdbXmlLoc) {
			// Put the PDB XML file in the same location as the PDB file
			case SAME_AS_PDB:
				if (pdbFile != null) {
					pdbXmlFile = new File(pdbFile.getParentFile(), pdbXmlFilename);
				}
				else {
					fail("Does not make sense to create a .pdb.xml file in the same directory as " +
						"the .pdb file when there is no .pdb file!");
				}
				break;

			// Put the PDB XML file in the <temp>/pdb_xml directory
			case OWN_DIR:
				// Create directory that will server as .pdb.xml location
				createDirectory(pdbXmlDir);
				filesCreated.add(pdbXmlDir);

				pdbXmlFile = new File(pdbXmlDir, pdbXmlFilename);
				break;

			// Do not create a PDB XML file
			case NONE:
				break;

			default:
				fail("Unrecognized pdbXmlLocation choice: " + pdbXmlLoc);

		}

		if (pdbXmlFile != null) {
			createFile(pdbXmlFile);
			filesCreated.add(pdbXmlFile);
		}

		verifyFilesCreated(pdbLoc, pdbXmlLoc);

		return filesCreated;
	}

	private void verifyFilesCreated(PdbLocation pdbLoc, PdbXmlLocation pdbXmlLoc) {

		File expectedDir1, expectedDir2;

		switch (pdbLoc) {
			case NONE:
				assertNull(pdbFile);
				break;

			case SAME_AS_EXE_SUBDIR:
				assertNotNull(pdbFile);
				expectedDir1 = new File(fileLocation, pdbFilename);
				expectedDir2 = new File(expectedDir1, guidAgeCombo);
				assertEquals(expectedDir2, pdbFile.getParentFile());
				break;

			case SAME_AS_EXE_NO_SUBDIR:
				assertNotNull(pdbFile);
				assertEquals(fileLocation, pdbFile.getParentFile());
				break;

			case SYMBOLS_SUBDIR:
				assertNotNull(pdbFile);
				expectedDir1 = new File(symbolsFolder, pdbFilename);
				expectedDir2 = new File(expectedDir1, guidAgeCombo);
				assertEquals(expectedDir2, pdbFile.getParentFile());
				break;

			case SYMBOLS_NO_SUBDIR:
				assertNotNull(pdbFile);
				assertEquals(symbolsFolder, pdbFile.getParentFile());
				break;

			default:
				fail("Unrecognized pdbLocation choice: " + pdbLoc);
		}

		switch (pdbXmlLoc) {
			case SAME_AS_PDB:
				assertNotNull(pdbXmlFile);
				assertEquals(pdbXmlFile.getParentFile(), pdbFile.getParentFile());
				break;

			case OWN_DIR:
				assertNotNull(pdbXmlFile);
				assertEquals(pdbXmlFile.getParentFile(), pdbXmlDir);
				break;

			case NONE:
				assertNull(pdbXmlFile);
				break;
		}
	}

	private void deleteCreatedFiles(List<File> filesToDelete) {
		// Delete in the reverse order the files were added
		for (int i = filesToDelete.size() - 1; i >= 0; i--) {
			filesToDelete.get(i).delete();
		}
	}

	/**
	 * notepad.pdb is here: <temp>/symbols/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * notepad.pdb.xml does not exist
	 * Repo location left alone (default)
	 * 
	 * PDB file should not be found, since default repo does not point to symbols folder.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb1() throws Exception {

		createdFiles = null;

		createdFiles = createFiles(PdbLocation.SYMBOLS_SUBDIR, PdbXmlLocation.NONE);
		File pdb = PdbParser.findPDB(testProgram, false, noSuchSymbolsRepoDir);

		// Should not find anything since repo is set to an invalid path
		assertNull(pdb);

	}

	/**
	 * notepad.pdb is here: <temp>/symbols/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * notepad.pdb.xml does not exist
	 * Repo location set to <temp>/symbols
	 * 
	 * On Windows, PDB file should be found.
	 * On non-Windows, Pdb file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb2() throws Exception {

		createdFiles = createFiles(PdbLocation.SYMBOLS_SUBDIR, PdbXmlLocation.NONE);

		File pdb = PdbParser.findPDB(testProgram, false, symbolsFolder);

		assertNotNull(pdb);
		assertEquals(pdbFile, pdb);

	}

	/**
	 * notepad.pdb is here: <temp>/symbols/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * notepad.pdb.xml is here: <temp>/symbols/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * Repo location set to <temp>/symbols
	 * 
	 * On Windows, PDB file should be found.
	 * On non-Windows, PDB XML file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb3() throws Exception {

		createdFiles = createFiles(PdbLocation.SYMBOLS_SUBDIR, PdbXmlLocation.SAME_AS_PDB);

		File pdb = PdbParser.findPDB(testProgram, false, symbolsFolder);

		assertNotNull(pdb);

		if (PdbParser.onWindows) {
			assertEquals(pdbFile, pdb);
		}
		else {
			assertEquals(pdbXmlFile, pdb);
		}
	}

	/**
	 * notepad.pdb is here: <temp>/symbols/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * notepad.pdb.xml is here: <temp>/pdb_xml/
	 * Repo location set to <temp>/symbols
	 * 
	 * On Windows, PDB file should be found.
	 * On non-Windows, PDB files should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb4() throws Exception {

		createdFiles = createFiles(PdbLocation.SYMBOLS_SUBDIR, PdbXmlLocation.OWN_DIR);

		File pdb = PdbParser.findPDB(testProgram, false, symbolsFolder);

		assertNotNull(pdb);
		assertEquals(pdb, pdb);

	}

	/**
	 * notepad.pdb is here: <temp>/symbols/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * notepad.pdb.xml is here: <temp>/pdb_xml/
	 * Repo location set to <temp>/pdb_xml
	 * 
	 * On Windows, PDB XML file should be found.
	 * On non-Windows, PDB XML file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb5() throws Exception {

		createdFiles = createFiles(PdbLocation.SYMBOLS_SUBDIR, PdbXmlLocation.OWN_DIR);

		File pdb = PdbParser.findPDB(testProgram, false, pdbXmlDir);

		assertNotNull(pdb);

		if (PdbParser.onWindows) {
			assertEquals(pdbXmlFile, pdb);
		}
		else {
			assertEquals(pdbXmlFile, pdb);
		}
	}

	/**
	 * notepad.pdb is here: <temp>/symbols/
	 * notepad.pdb.xml does not exist
	 * Repo location set to <temp>/symbols
	 * 
	 * On Windows, PDB file should be found.
	 * On non-Windows, PDB file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb6() throws Exception {

		createdFiles = createFiles(PdbLocation.SYMBOLS_NO_SUBDIR, PdbXmlLocation.NONE);

		File pdb = PdbParser.findPDB(testProgram, false, symbolsFolder);

		assertNotNull(pdb);
		assertEquals(pdbFile, pdb);

	}

	/**
	 * notepad.pdb is here: <temp>/symbols/
	 * notepad.pdb.xml does not exist
	 * Repo location set to <temp>/pdb_xml/
	 * 
	 * PDB file should not be found, since default repo does not point to symbols folder.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb7() throws Exception {

		createdFiles = createFiles(PdbLocation.SYMBOLS_NO_SUBDIR, PdbXmlLocation.NONE);

		File pdb = PdbParser.findPDB(testProgram, false, pdbXmlDir);

		// Should not find anything since repo is set to an invalid path
		assertNull(pdb);
	}

	/**
	 * notepad.pdb is here: <temp>/symbols/
	 * notepad.pdb.xml is here: <temp>/symbols/
	 * Repo location set to <temp>/symbols
	 * 
	 * On Windows, PDB file should be found.
	 * On non-Windows, PDB XML file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb8() throws Exception {

		createdFiles = createFiles(PdbLocation.SYMBOLS_NO_SUBDIR, PdbXmlLocation.SAME_AS_PDB);

		File pdb = PdbParser.findPDB(testProgram, false, symbolsFolder);

		assertNotNull(pdb);

		if (PdbParser.onWindows) {
			assertEquals(pdbFile, pdb);
		}
		else {
			assertEquals(pdbXmlFile, pdb);
		}
	}

	/**
	 * notepad.pdb is here: <temp>/symbols/
	 * notepad.pdb.xml is here: <temp>/pdb_xml/
	 * Repo location set to <temp>/symbols
	 * 
	 * On Windows, PDB file should be found.
	 * On non-Windows, PDB file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb9() throws Exception {

		createdFiles = createFiles(PdbLocation.SYMBOLS_NO_SUBDIR, PdbXmlLocation.OWN_DIR);

		File pdb = PdbParser.findPDB(testProgram, false, symbolsFolder);

		assertNotNull(pdb);
		assertEquals(pdbFile, pdb);

	}

	/**
	 * notepad.pdb is here: <temp>/symbols/
	 * notepad.pdb.xml is here: <temp>/pdb_xml/
	 * Repo location set to <temp>/pdb_xml
	 * 
	 * On Windows, PDB XML file should be found.
	 * On non-Windows, PDB XML file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb10() throws Exception {

		createdFiles = createFiles(PdbLocation.SYMBOLS_NO_SUBDIR, PdbXmlLocation.OWN_DIR);

		File pdb = PdbParser.findPDB(testProgram, false, pdbXmlDir);

		assertNotNull(pdb);

		if (PdbParser.onWindows) {
			assertEquals(pdbXmlFile, pdb);
		}
		else {
			assertEquals(pdbXmlFile, pdb);
		}
	}

	/**
	 * notepad.pdb is here: <temp>/exe/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * notepad.pdb.xml does not exist
	 * Repo location set to <temp>/exe/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * 
	 * On Windows, PDB file should be found
	 * On non-Windows, PDB file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb11() throws Exception {

		createdFiles = createFiles(PdbLocation.SAME_AS_EXE_SUBDIR, PdbXmlLocation.NONE);

		File pdb = PdbParser.findPDB(testProgram, false, pdbFile.getParentFile());

		assertNotNull(pdb);
		assertEquals(pdbFile, pdb);

	}

	/**
	 * notepad.pdb is here: <temp>/exe/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * notepad.pdb.xml is here: <temp>/exe/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * Repo location set to default location
	 * 
	 * PDB file should not be found, since default repo does not point to exe folder.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb12() throws Exception {

		createdFiles = createFiles(PdbLocation.SAME_AS_EXE_SUBDIR, PdbXmlLocation.SAME_AS_PDB);

		File pdb = PdbParser.findPDB(testProgram, false, noSuchSymbolsRepoDir);

		// Should not find anything since repo is set to an invalid path
		assertNull(pdb);
	}

	/**
	 * notepad.pdb is here: <temp>/exe/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * notepad.pdb.xml is here: <temp>/exe/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * Repo location set to <temp>/exe/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * 
	 * On Windows, PDB file should be found.
	 * On non-Windows, PDB XML file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb13() throws Exception {

		createdFiles = createFiles(PdbLocation.SAME_AS_EXE_SUBDIR, PdbXmlLocation.SAME_AS_PDB);

		File pdb = PdbParser.findPDB(testProgram, false, pdbFile.getParentFile());

		assertNotNull(pdb);

		if (PdbParser.onWindows) {
			assertEquals(pdbFile, pdb);
		}
		else {
			assertEquals(pdbXmlFile, pdb);
		}
	}

	/**
	 * notepad.pdb is here: <temp>/exe/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * notepad.pdb.xml is here: <temp>/pdb_xml/
	 * Repo location set to <temp>/exe/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * 
	 * On Windows, PDB file should be found.
	 * On non-Windows, PDB file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb14() throws Exception {

		createdFiles = createFiles(PdbLocation.SAME_AS_EXE_SUBDIR, PdbXmlLocation.OWN_DIR);

		File pdb = PdbParser.findPDB(testProgram, false, pdbFile.getParentFile());

		assertNotNull(pdb);
		assertEquals(pdbFile, pdb);

	}

	/**
	 * notepad.pdb is here: <temp>/exe/notepad.pdb/36CFD5F9888C4483B522B9DB242D84782/
	 * notepad.pdb.xml is here: <temp>/pdb_xml/
	 * Repo location set to <temp>/pdb_xml/
	 * 
	 * On Windows, PDB XML file should be found.
	 * On non-Windows, PDB XML file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb15() throws Exception {

		createdFiles = createFiles(PdbLocation.SAME_AS_EXE_SUBDIR, PdbXmlLocation.OWN_DIR);

		File pdb = PdbParser.findPDB(testProgram, false, pdbXmlFile.getParentFile());

		assertNotNull(pdb);

		if (PdbParser.onWindows) {
			assertEquals(pdbXmlFile, pdb);
		}
		else {
			assertEquals(pdbXmlFile, pdb);
		}
	}

	/**
	 * notepad.pdb is here: <temp>/exe/
	 * notepad.pdb.xml does not exist
	 * Repo location set to default location
	 * 
	 * Special case: Even if repo location is set to a location that doesn't contain a .pdb or
	 *      .pdb.xml file, it will still be found if there is a file in the same folder as the binary
	 * 
	 * On Windows, PDB file should be found.
	 * On non-Windows, PDB file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb16() throws Exception {

		createdFiles = createFiles(PdbLocation.SAME_AS_EXE_NO_SUBDIR, PdbXmlLocation.NONE);

		File pdb = PdbParser.findPDB(testProgram, false, noSuchSymbolsRepoDir);

		assertNotNull(pdb);
		assertEquals(pdbFile, pdb);

	}

	/**
	 * notepad.pdb is here: <temp>/exe/
	 * notepad.pdb.xml does not exist
	 * Repo location set to <temp>/exe/
	 * 
	 * On Windows, PDB file should be found.
	 * On non-Windows, PDB file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb17() throws Exception {

		createdFiles = createFiles(PdbLocation.SAME_AS_EXE_NO_SUBDIR, PdbXmlLocation.NONE);

		File pdb = PdbParser.findPDB(testProgram, false, pdbFile.getParentFile());

		assertNotNull(pdb);
		assertEquals(pdbFile, pdb);

	}

	/**
	 * notepad.pdb is here: <temp>/exe/
	 * notepad.pdb.xml does not exist
	 * Repo location set to <temp>/pdb_xml/
	 * 
	 * Special case: Even if repo location is set to a location that doesn't contain a .pdb or
	 *      .pdb.xml file, it will still be found if there is a file in the same folder as the binary
	 * 
	 * On Windows, PDB file should be found.
	 * On non-Windows, PDB file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb18() throws Exception {

		createdFiles = createFiles(PdbLocation.SAME_AS_EXE_NO_SUBDIR, PdbXmlLocation.NONE);

		File pdb = PdbParser.findPDB(testProgram, false, pdbXmlDir);

		assertNotNull(pdb);
		assertEquals(pdbFile, pdb);

	}

	/**
	 * notepad.pdb is here: <temp>/exe/
	 * notepad.pdb.xml is here: <temp>/exe/
	 * Repo location set to the default location
	 * 
	 * Special case: Even if repo location is set to a location that doesn't contain a .pdb or
	 *      .pdb.xml file, it will still be found if there is a file in the same folder as the binary
	 * 
	 * On Windows, PDB file should be found.
	 * On non-Windows, PDB XML file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb19() throws Exception {

		createdFiles = createFiles(PdbLocation.SAME_AS_EXE_NO_SUBDIR, PdbXmlLocation.SAME_AS_PDB);

		File pdb = PdbParser.findPDB(testProgram, false, noSuchSymbolsRepoDir);

		assertNotNull(pdb);

		if (PdbParser.onWindows) {
			assertEquals(pdbFile, pdb);
		}
		else {
			assertEquals(pdbXmlFile, pdb);
		}
	}

	/**
	 * notepad.pdb is here: <temp>/exe/
	 * notepad.pdb.xml is here: <temp>/exe/
	 * Repo location set to <temp>/exe/
	 * 
	 * On Windows, PDB file should be found.
	 * On non-Windows, PDB XML file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb20() throws Exception {

		createdFiles = createFiles(PdbLocation.SAME_AS_EXE_NO_SUBDIR, PdbXmlLocation.SAME_AS_PDB);

		File pdb = PdbParser.findPDB(testProgram, false, pdbFile.getParentFile());

		assertNotNull(pdb);

		if (PdbParser.onWindows) {
			assertEquals(pdbFile, pdb);
		}
		else {
			assertEquals(pdbXmlFile, pdb);
		}
	}

	/**
	 * notepad.pdb is here: <temp>/exe/
	 * notepad.pdb.xml is here: <temp>/pdb_xml/
	 * Repo location set to default location
	 * 
	 * On Windows, PDB file should be found (Repo path is invalid, so it looks in same location as exe).
	 * On non-Windows, PDB file should be found (Repo path is invalid, so it looks in same location as exe).
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb21() throws Exception {

		createdFiles = createFiles(PdbLocation.SAME_AS_EXE_NO_SUBDIR, PdbXmlLocation.OWN_DIR);

		File pdb = PdbParser.findPDB(testProgram, false, noSuchSymbolsRepoDir);

		assertNotNull(pdb);
		assertEquals(pdbFile, pdb);
	}

	/**
	 * notepad.pdb is here: <temp>/exe/
	 * notepad.pdb.xml is here: <temp>/pdb_xml/
	 * Repo location set to <temp>/exe/
	 * 
	 * On Windows, PDB file should be found
	 * On non-Windows, PDB file should be found.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb22() throws Exception {

		createdFiles = createFiles(PdbLocation.SAME_AS_EXE_NO_SUBDIR, PdbXmlLocation.OWN_DIR);

		File pdb = PdbParser.findPDB(testProgram, false, pdbFile.getParentFile());

		assertNotNull(pdb);
		assertEquals(pdbFile, pdb);
	}

	/**
	 * notepad.pdb is here: <temp>/exe/
	 * notepad.pdb.xml is here: <temp>/pdb_xml/
	 * Repo location set to <temp>/pdb_xml/
	 * 
	 * Special case: Even if repo location is set to a location that doesn't contain a .pdb or
	 *      .pdb.xml file, it will still be found if there is a file in the same folder as the binary
	 * 
	 * On Windows, PDB XML file should be found (looks first in user-defined repo location)
	 * On non-Windows, PDB XML file should be found
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb23() throws Exception {

		createdFiles = createFiles(PdbLocation.SAME_AS_EXE_NO_SUBDIR, PdbXmlLocation.OWN_DIR);

		File pdb = PdbParser.findPDB(testProgram, false, pdbXmlDir);

		assertNotNull(pdb);

		if (PdbParser.onWindows) {
			assertEquals(pdbXmlFile, pdb);
		}
		else {
			assertEquals(pdbXmlFile, pdb);
		}
	}

	/**
	 * notepad.pdb does not exist
	 * notepad.pdb.xml does not exist
	 * Repo location set to the default location
	 * 
	 * On Windows, no file should be found
	 * On non-Windows, no file should be found
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb24() throws Exception {

		createdFiles = createFiles(PdbLocation.NONE, PdbXmlLocation.NONE);

		File pdb = PdbParser.findPDB(testProgram, false, noSuchSymbolsRepoDir);
		assertNull(pdb);

	}

	/**
	 * notepad.pdb does not exist
	 * notepad.pdb.xml is here: <temp>/pdb_xml/
	 * Repo location set to the default location
	 * 
	 * On Windows, no file should be found
	 * On non-Windows, no file should be found
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb25() throws Exception {

		createdFiles = createFiles(PdbLocation.NONE, PdbXmlLocation.OWN_DIR);

		File pdb = PdbParser.findPDB(testProgram, false, noSuchSymbolsRepoDir);
		assertNull(pdb);

	}

	/**
	 * notepad.pdb does not exist
	 * notepad.pdb.xml is here: <temp>/pdb_xml/
	 * Repo location set to <temp>/pdb_xml/
	 * 
	 * On Windows, PDB XML file should be found
	 * On non-Windows, PDB XML file should be found
	 * 
	 * @throws Exception
	 */
	@Test
	public void testFindPdb26() throws Exception {

		createdFiles = createFiles(PdbLocation.NONE, PdbXmlLocation.OWN_DIR);

		File pdb = PdbParser.findPDB(testProgram, false, pdbXmlDir);

		assertNotNull(pdb);

		if (PdbParser.onWindows) {
			assertEquals(pdbXmlFile, pdb);
		}
		else {
			assertEquals(pdbXmlFile, pdb);
		}
	}

	private void createDirectory(File directory) {
		directory.mkdir();
		if (!directory.isDirectory()) {
			fail("Should have created directory: " + directory);
		}
	}

	private void createFile(File file) {
		boolean createSuccess;

		try {
			createSuccess = file.createNewFile();

			if (!createSuccess) {
				fail("Failed creation of file: " + file);
			}
		}
		catch (IOException ioe) {
			fail("Exception while creating: " + file);
		}
	}

	private void buildPdbXml() throws Exception {
		// Write to the pdb.xml file
		FileWriter xmlFileWriter;

		try {
			xmlFileWriter = new FileWriter(pdbXmlFile);
			BufferedWriter xmlBuffWriter = new BufferedWriter(xmlFileWriter);

			xmlBuffWriter.write("<pdb file=\"" + pdbFilename + "\" exe=\"" + programBasename +
				"\" guid=\"{" + notepadGUID.toUpperCase() + "}\" age=\"" +
				Integer.parseInt(notepadAge, 16) + "\">\n");

//			xmlBuffWriter.write("<enums></enums>\n");
//			xmlBuffWriter.write("<datatypes></datatypes>\n");
//			xmlBuffWriter.write("<typedefs></typedefs>\n");
//			xmlBuffWriter.write("<classes></classes>\n");

			xmlBuffWriter.write("<functions>\n");

			for (TestFunction currentFunction : programFunctions) {
				xmlBuffWriter.write("<function name=\"" + currentFunction.getName() +
					"\" address=\"" + currentFunction.getAddress() + "\" length=\"" +
					currentFunction.getLength() + "\"></function>\n");
			}

			xmlBuffWriter.write("</functions>\n");

//			xmlBuffWriter.write("<tables></tables>");

			xmlBuffWriter.write("</pdb>\n");
			xmlBuffWriter.close();
		}
		catch (IOException ioe) {
			fail("IOException writing to temporary file (" + pdbXmlFile + "). " +
				ioe.toString());
		}

	}

	@Test
	public void testApplyFunctions() throws Exception {

		createdFiles = createFiles(PdbLocation.NONE, PdbXmlLocation.OWN_DIR);

		buildPdbXml();

		File pdb = PdbParser.findPDB(testProgram, false, pdbXmlDir);

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(testProgram);
		DataTypeManagerService dataTypeManagerService = mgr.getDataTypeManagerService();
		PdbParser parser =
			new PdbParser(pdb, testProgram, dataTypeManagerService, false, TaskMonitor.DUMMY);

		parser.openDataTypeArchives();
		parser.parse();
		parser.applyTo(new MessageLog());

		// Now check program to see if the function has been successfully applied
		AddressFactory addressFactory = testProgram.getAddressFactory();

		FunctionManager functionManager = testProgram.getFunctionManager();

		for (TestFunction currentFunction : programFunctions) {
			String currentFunctionAddress = currentFunction.getAddress();
			FunctionDB possibleFunction = (FunctionDB) functionManager.getFunctionAt(
				addressFactory.getAddress(currentFunctionAddress));

			assertNotNull("Expected function at address: " + currentFunctionAddress,
				possibleFunction);
			assertEquals("function1", possibleFunction.getName());
		}
	}
}

// Test loading of file with wrong GUID/Age (PdbParserNEW.parse() --> hasErrors() and hasWarnings())

// Test malformed XML

// Test incomplete information for each type of information

// Test file having name of a folder that is to be created.

class TestFunction {

	private String name, address, length;

	public TestFunction(String name, String address, String length) {
		this.name = name;
		this.address = address;
		this.length = length;
	}

	public String getName() {
		return name;
	}

	public String getAddress() {
		return address;
	}

	public String getLength() {
		return length;
	}

}
