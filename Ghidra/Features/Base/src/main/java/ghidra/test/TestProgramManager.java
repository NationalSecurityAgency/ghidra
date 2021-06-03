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
package ghidra.test;

import java.io.*;
import java.util.*;

import db.DBConstants;
import db.DBHandle;
import db.buffers.BufferFile;
import generic.test.AbstractGTest;
import generic.test.AbstractGenericTest;
import ghidra.app.util.xml.*;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.*;
import ghidra.framework.store.db.PrivateDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * A class to handle locating, opening and caching (within a JVM) programs in the test
 * environment.  (This code was formerly inside of TestEnv.)
 */
public class TestProgramManager {

	private final Map<String, PrivateDatabase> testPrograms = new HashMap<>();
	private final Set<Program> openTestPrograms = new HashSet<>();

	private static final String DB_DIR_NAME = "db";
	private static File dbTestDir;

	public void add(Program p) {
		openTestPrograms.add(p);
	}

	/**
	 * Open a read-only test program from the test data directory.
	 * This program must be released prior to disposing this test environment.
	 * NOTE: Some tests rely on this method returning null when file does
	 * not yet exist within the resource area (e.g., test binaries for P-Code Tests)
	 *
	 * @param progName name of program database within the test data directory.
	 * @return program or null if program file not found
	 */
	public ProgramDB getProgram(String progName) {

		if (progName.endsWith(".gzf")) {
			progName = progName.substring(0, progName.length() - 4);
		}

		try {
			PrivateDatabase db = testPrograms.get(progName);
			if (db != null) {
				ProgramDB program = openProgram(progName, db);
				openTestPrograms.add(program);
				return program;
			}

			File dbDir = new File(getDbTestDir(), NamingUtilities.mangle(progName) + ".db");
			db = loadDBFromDirectory(db, dbDir);

			if (db == null) {
				db = createNewDB(progName, db, dbDir);
			}

			if (db == null) {
				return null;
			}

			ProgramDB program = openProgram(progName, db);

			openTestPrograms.add(program);
			return program;

		}
		catch (Exception e) {
			throw new RuntimeException(
				"Failed to load test program " + progName + " because: " + e.getMessage(), e);
		}
	}

	public Set<Program> getOpenPrograms() {
		return Collections.unmodifiableSet(openTestPrograms);
	}

	public void addOpenProgram(Program program) {
		openTestPrograms.add(program);
	}

	public void release(Program program) {

		List<Object> consumers = program.getConsumerList();
		if (consumers.contains(this)) {
			program.release(this);
		}

		if (!program.isClosed()) {
			return;
		}

		openTestPrograms.remove(program);
	}

	/**
	 * Save a program to the cached program store.  A SaveAs will be performed on the
	 * program to its cached storage location.
	 * 
	 * @param progName program name
	 * @param program program object
	 * @param replace if true any existing cached database with the same name will be replaced
	 * @param monitor task monitor
	 * @throws IOException if the database cannot be created
	 * @throws DuplicateNameException if already cached
	 * @throws CancelledException if the save operation is cancelled
	 */
	public void saveToCache(String progName, ProgramDB program, boolean replace,
			TaskMonitor monitor) throws IOException, DuplicateNameException, CancelledException {

		if (progName.endsWith(".gzf")) {
			progName = progName.substring(0, progName.length() - 4);
		}

		if (testPrograms.containsKey(progName)) {
			if (!replace) {
				throw new DuplicateNameException(progName + " already cached");
			}
			testPrograms.remove(progName);
		}

		File dbDir = new File(getDbTestDir(), NamingUtilities.mangle(progName) + ".db");

		FileUtilities.deleteDir(dbDir);
		dbDir.mkdirs();

		DBHandle dbh = program.getDBHandle();
		BufferFile bfile = PrivateDatabase.createDatabase(dbDir, null, dbh.getBufferSize());
		program.getDBHandle().saveAs(bfile, true, monitor);

		testPrograms.put(progName, new PrivateDatabase(dbDir));

		Msg.info(this, "Stored unpacked program in TestEnv cache: " + progName);
	}

	/**
	 * Determine if the specified program already exists with the program cache
	 * @param name the program name
	 * @return true if the specified program already exists with the program cache
	 */
	public boolean isProgramCached(String name) {
		return testPrograms.containsKey(name);
	}

	/**
	 * Remove specified program from cache
	 * @param name the program name
	 */
	public void removeFromProgramCache(String name) {
		testPrograms.remove(name);
		FileUtilities.deleteDir(getDbDir(name));
	}

	public void disposeOpenPrograms() {
		Set<Program> copy = new HashSet<>(openTestPrograms);
		for (Program program : copy) {
			release(program);
			if (program instanceof ProgramDB) {
				((DomainObjectAdapterDB) program).getDBHandle().close();
			}
		}
	}

	public void markAllProgramsAsUnchanged() {
		for (Program program : openTestPrograms) {
			program.setTemporary(true);
		}
	}

	public void removeAllConsumersExcept(Program p, Object consumer) {
		p.getConsumerList().forEach(c -> {
			if (c != consumer) {
				p.release(c);
			}
		});
	}

	/**
	 * Copies the specified program zip file to the JUnit test project's root folder. <b>This
	 * means that the program will appear in the FrontEndTool as part of the project.</b>  That is
	 * the only reason to use this method vice openProgram().
	 *
	 * @param project the project into which the file will be restored
	 * @param programName the name of the program zip file without the ".gzf" extension
	 * @return the file
	 * @throws FileNotFoundException if the file cannot be found 
	 */
	public DomainFile addProgramToProject(Project project, String programName)
			throws FileNotFoundException {

		DomainFolder rootFolder = project.getProjectData().getRootFolder();
		return addProgramToProject(rootFolder, programName);
	}

	/**
	 * Copies the specified program zip file to the JUnit test project's folder. <b>This
	 * means that the program will appear in the FrontEndTool as part of the project.</b>  That is
	 * the only reason to use this method vice openProgram().
	 *
	 * @param folder the folder into which the domain file will be inserted
	 * @param programName the name of the program zip file without the ".gzf" extension.
	 * @return the file
	 * @throws FileNotFoundException if the file cannot be found 
	 */
	public DomainFile addProgramToProject(DomainFolder folder, String programName)
			throws FileNotFoundException {

		File gzf = AbstractGenericTest.getTestDataFile(programName + ".gzf");

		// handle program names that are relative paths
		String name = gzf.getName();
		name = name.substring(0, name.indexOf("."));

		int oneUp = 0;
		while (true) {
			try {
				DomainFile df = folder.createFile(name, gzf, TaskMonitor.DUMMY);
				AbstractGenericTest.waitForPostedSwingRunnables();
				DomainObject dobj = df.getDomainObject(this, true, false, null);
				try {
					if (dobj.isChanged()) {
						dobj.save("upgrade", null);
					}
				}
				finally {
					dobj.release(this);
				}
				return df;
			}
			catch (VersionException e) {
				throw new RuntimeException(
					"Program version is more recent than this code: " + programName);
			}
			catch (CancelledException e) {
				// can't happen--null monitor
			}
			catch (InvalidNameException e) {
				throw new AssertException("Got invalid name exception: " + e);
			}
			catch (DuplicateFileException e) {
				++oneUp;
				name = name + "_" + oneUp;
			}
			catch (IOException e) {
				String msg = e.getMessage();
				if (msg == null) {
					msg = e.toString();
				}
				throw new RuntimeException(
					"Failed to restore test program: " + programName + " - " + msg);
			}
		}
	}
//==================================================================================================
// Private Methods
//==================================================================================================

	private ProgramDB openProgram(String progName, PrivateDatabase db) throws Exception {

		ProgramDB program = null;
		DBHandle dbh = null;
		boolean success = false;
		try {
			dbh = db.open(TaskMonitor.DUMMY);
			program = new ProgramDB(dbh, DBConstants.UPDATE, null, this);
			success = true;
		}
		catch (VersionException ve) {
			if (!ve.isUpgradable()) {
				throw ve;
			}

			if (dbh != null) {
				dbh.close();
			}
			dbh = null;

			// this property is set when running from the nightly batch build
			String message = System.getProperty("upgradeProgramErrorMessage");
			if (message == null) {
				message = "WARNING! Attempting data upgrade for ";
			}

			Msg.info(this, message + " '" + progName + "'");
			long startTime = System.currentTimeMillis();
			upgradeDatabase(db);
			long endTime = System.currentTimeMillis();

			message = System.getProperty("upgradeTimeErrorMessage");
			if (message == null) {
				message = "Upgrade Time (ms): ";
			}

			Msg.info(this, message + (endTime - startTime));
			dbh = db.open(TaskMonitor.DUMMY);
			program = new ProgramDB(dbh, DBConstants.UPDATE, null, this);
			dbh = null;
			success = true;
		}
		finally {
			if (!success && dbh != null) {
				dbh.close();
			}
		}

		DomainFile df = program.getDomainFile();
		if (!df.isInWritableProject()) {
			df.setName(progName);
		}
		return program;
	}

	private PrivateDatabase createNewDB(String programName, PrivateDatabase db, File dbDir)
			throws Exception {

		// Remove old database if it exists
		if (db != null) {
			FileUtilities.deleteDir(dbDir);
		}

		File gzf = AbstractGenericTest.findTestDataFile(programName + ".gzf");
		if (gzf != null && gzf.exists()) {
			Msg.info(this, "Unpacking: " + gzf);
			db = new PrivateDatabase(dbDir, gzf, TaskMonitor.DUMMY);
			testPrograms.put(programName, db);
			return db;
		}

		File xml = AbstractGenericTest.findTestDataFile(programName + ".xml");
		if (xml == null || !xml.exists()) {
			Msg.info(this, "Test program not found: " + programName);
			return null;
		}

		Msg.info(this, "Importing: " + xml);

		LanguageService languageService = DefaultLanguageService.getLanguageService();
		ProgramXmlMgr mgr = new ProgramXmlMgr(xml);
		ProgramInfo info = mgr.getProgramInfo();
		Language language = null;
		try {
			language = languageService.getLanguage(info.languageID);
		}
		catch (LanguageNotFoundException e) {
			Processor processor = null;
			try {
				processor = Processor.toProcessor(info.processorName);
			}
			catch (ProcessorNotFoundException pnfe) {
				//silently fail
			}
			language = languageService.getDefaultLanguage(processor);

		}

		CompilerSpec compilerSpec = null;
		if (info.compilerSpecID != null) {
			compilerSpec = language.getCompilerSpecByID(info.compilerSpecID);
		}
		if (compilerSpec == null) {
			compilerSpec = language.getDefaultCompilerSpec();
		}

		// Import program
		ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
		ProgramDB p = new ProgramDB(programName, language, compilerSpec, this);
		int txId = p.startTransaction("Import");
		try {
			mgr.read(p, monitor, new XmlProgramOptions());
		}
		finally {
			p.endTransaction(txId, true);
		}

		// Save program database and add to cache
		DBHandle dbh = p.getDBHandle();
		BufferFile bfile = PrivateDatabase.createDatabase(dbDir, null, dbh.getBufferSize());
		p.getDBHandle().saveAs(bfile, true, monitor);
		p.release(this);

		db = new PrivateDatabase(dbDir);

		Msg.info(this, "Import of " + programName + " complete.");

		testPrograms.put(programName, db);
		return db;
	}

	private File getDbDir(String progName) {
		return new File(getDbTestDir(), NamingUtilities.mangle(progName) + ".db");
	}

	public static void setDbTestDir(File newDbTestDir) {
		Msg.debug(TestProgramManager.class,
			"Changing default db test directory to " + newDbTestDir);
		dbTestDir = newDbTestDir;
	}

	public static File getDbTestDir() {
		if (dbTestDir == null) {
			dbTestDir = getTestDBDirectory();
		}
		return dbTestDir;
	}

	private static File getTestDBDirectory() {
		String testDirPath = AbstractGTest.getTestDirectoryPath();
		File dir = new File(testDirPath, DB_DIR_NAME);
		dir.mkdir();
		return dir;
	}

	private PrivateDatabase loadDBFromDirectory(PrivateDatabase db, File dbDir) {
		if (!dbDir.isDirectory()) {
			return null;
		}

		try {
			db = new PrivateDatabase(dbDir);
		}
		catch (IOException e) {
			// squash and handle below
		}

		if (db == null || db.getCurrentVersion() == 0) {
			FileUtilities.deleteDir(dbDir);
		}

		return db;
	}

	private void upgradeDatabase(PrivateDatabase db) throws Exception {

		DBHandle dbh = db.openForUpdate(TaskMonitor.DUMMY);
		try {
			ProgramDB program =
				new ProgramDB(dbh, DBConstants.UPGRADE, TaskMonitor.DUMMY, this);
			if (dbh != null) {
				dbh.save(null, null, TaskMonitor.DUMMY);
			}
			dbh = null;
			program.release(this);
		}
		finally {
			if (dbh != null) {
				dbh.close();
			}
		}
	}
}
