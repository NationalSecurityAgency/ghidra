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
package ghidra.base.project;

import static generic.test.AbstractGTest.*;
import static generic.test.AbstractGenericTest.invokeInstanceMethod;
import static generic.test.TestUtils.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.StringUtils;

import generic.test.AbstractGenericTest;
import generic.test.TestUtils;
import ghidra.framework.data.*;
import ghidra.framework.model.*;
import ghidra.framework.remote.User;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.FileSystemEventManager;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.program.model.listing.Program;
import ghidra.test.TestEnv;
import ghidra.test.TestProgramManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import junit.framework.AssertionFailedError;

/**
 * This class represents the idea of a shared Ghidra project.  Each project is associated with
 * a {@link FakeRepository}.
 * 
 * <P>This shared project is intended to allow for easy testing of changes to {@link DomainFile}s
 * under version control.
 * 
 * <P>If you do not need to test version controlled files or any other multi-user interaction, 
 * then do not use this class, but instead use {@link TestEnv}.
 * 
 * @see FakeRepository
 */
public class FakeSharedProject {

	private GhidraProject gProject;
	private TestProgramManager programManager = new TestProgramManager();
	private FakeRepository repo;

	public FakeSharedProject(FakeRepository repo, User user) throws IOException {

		this.repo = repo;
		String projectDirPath = AbstractGenericTest.getTestDirectoryPath();
		gProject =
			GhidraProject.createProject(projectDirPath, "TestProject_" + user.getName(), true);
		gProject.setDeleteOnClose(true);

		LocalFileSystem fs = repo.getSharedFileSystem();
		if (fs != null) {
			// first project will keeps its versioned file system
			setVersionedFileSystem(fs);
		}
	}

	FakeSharedProject(User user) throws IOException {

		String projectDirPath = AbstractGenericTest.getTestDirectoryPath();
		gProject =
			GhidraProject.createProject(projectDirPath, "TestProject_" + user.getName(), true);
	}

	// Note: this how we share multiple projects
	void setVersionedFileSystem(LocalFileSystem fs) {

		ProjectFileManager fm = getProjectFileManager();
		invokeInstanceMethod("setVersionedFileSystem", fm, argTypes(FileSystem.class), args(fs));
	}

	/**
	 * Get the ghidra project
	 * @return the ghidra project
	 */
	public GhidraProject getGhidraProject() {
		return gProject;
	}

	/**
	 * Gets the project file manager
	 * 
	 * @return the project file manager
	 */
	public ProjectFileManager getProjectFileManager() {
		return (ProjectFileManager) gProject.getProject().getProjectData();
	}

	/**
	 * Gets the root folder of this project
	 * 
	 * @return the root folder of this project
	 */
	public RootGhidraFolder getRootFolder() {
		ProjectFileManager pfm = getProjectFileManager();
		return (RootGhidraFolder) pfm.getRootFolder();
	}

	/**
	 * Adds the file with the given name to this fake project.  The file must exist in the
	 * test data area. The file will be put in the root folder of the project.
	 * 
	 * <P>Note: this does NOT add the file to version control.  Thus, the file will not be 
	 * visible to other projects in the parent repo.  To add to version control, call
	 * {@link #addToVersionControl(DomainFile, boolean)}.
	 * 
	 * @param filename the filename (including path of the real file on disk)
	 * @return the newly created domain file
	 * @throws Exception if there are any issues finding or adding the file to the project
	 */
	public DomainFile addDomainFile(String filename) throws Exception {
		Project project = getGhidraProject().getProject();
		DomainFile df = programManager.addProgramToProject(project, filename);
		return df;
	}

	/**
	 * Adds the file with the given name to this fake project.  The file must exist in the
	 * test data area. 
	 * 
	 * <P>Note: this does NOT add the file to version control.  Thus, the file will not be 
	 * visible to other projects in the parent repo.  To add to version control, call
	 * {@link #addToVersionControl(DomainFile, boolean)}.
	 * 
	 * @param parentPath the destination parent folder path
	 * @param filename the filename (including path of the real file on disk)
	 * @return the newly created domain file
	 * @throws Exception if there are any issues finding or adding the file to the project
	 */
	public DomainFile addDomainFile(String parentPath, String filename) throws Exception {
		DomainFolder parent = getFolder(parentPath);
		DomainFile df = programManager.addProgramToProject(parent, filename);
		return df;
	}

	/**
	 * Gets the domain file for the given name.  The file must have been added to the 
	 * project via one of:
	 * <ul>
	 * 	<li>calling {@link #addDomainFile(String)}</li>
	 *  <li>Adding a versioned file to another project that shares the same repo with this project</li>
	 * </ul>
	 * @param filepath the filename
	 * @return the file
	 */
	public DomainFile getDomainFile(String filepath) {
		Project project = getGhidraProject().getProject();
		ProjectData projectData = project.getProjectData();
		DomainFile df;
		if (filepath.startsWith("/")) {
			df = projectData.getFile(filepath);
		}
		else {
			DomainFolder rootFolder = projectData.getRootFolder();
			df = rootFolder.getFile(filepath);
		}

		return df;
	}

	/**
	 * Gets the domain file for the given name.  The file must have been added to the 
	 * project via one of:
	 * <ul>
	 * 	<li>calling {@link #addDomainFile(String)}</li>
	 *  <li>Adding a versioned file to another project that shares the same repo with this project</li>
	 * </ul>
	 * @param filename the filename
	 * @return the file
	 */
	public DomainFile getDomainFile(String parentPath, String filename) throws Exception {
		DomainFolder folder = getFolder(parentPath);
		DomainFile df = folder.getFile(filename);
		return df;
	}

	/**
	 * Creates a folder by the given name in the given parent folder, creating the parent 
	 * folder if needed
	 * 
	 * @param parentPath the parent folder path
	 * @param name the name of the folder to create
	 * @return the created folder
	 * @throws Exception if there are any exceptions creating the folder
	 */
	public DomainFolder createFolder(String path) throws Exception {
		DomainFolder folder = getFolder(path);
		return folder;
	}

	/**
	 * Opens the the program by the given name.  The path can be a simple name or a relative or
	 * absolute path to the file within the project.
	 * 
	 * @param filePath the path to the file to open 
	 * @return the domain file
	 * @throws IllegalArgumentException if the given domain file is not in the project
	 * @throws Exception if there are any exceptions opening the program
	 */
	public Program openProgram(String filePath) throws Exception {

		DomainFile df = getDomainFile(filePath);
		if (df == null) {
			throw new IllegalArgumentException(
				"DomainFile not in project.  You must first call addDomainFile(name)");
		}
		Program p = openProgram(df);
		return p;
	}

	/**
	 * Opens a program for the given domain file
	 * 
	 * @param df the domain file; cannot be null
	 * @return the opened program
	 * @throws Exception if there are any exceptions opening the program
	 */
	public Program openProgram(DomainFile df) throws Exception {

		assertFileInProject(df);

		Object consumer = programManager;
		Program p = (Program) df.getDomainObject(consumer, false, false, TaskMonitor.DUMMY);
		programManager.add(p);
		return p;
	}

	/**
	 * Closes the given program
	 * 
	 * @param p the program
	 */
	public void closeProgram(Program p) {
		programManager.release(p);
		assertTrue(p.getConsumerList().isEmpty());
	}

	/**
	 * Performs a check-in if the given file
	 * 
	 * @param df the domain file; cannot be null
	 * @param keepCheckedOut true to keep the file checked-out after the check-in completes
	 * @param comment the comment for the check-in
	 * @throws IllegalArgumentException if the given file has no changes to check-in or cannot
	 *         otherwise be checked-in
	 * @throws Exception if there are any exceptions performing the check-in
	 */
	public void checkin(DomainFile df, boolean keepCheckedOut, String comment) throws Exception {

		assertFileInProject(df);

		if (!df.canCheckin()) {
			throw new IllegalArgumentException("canCheckin() is false for " + df);
		}

		CheckinHandler ch = new CheckinHandler() {

			@Override
			public boolean keepCheckedOut() throws CancelledException {
				return keepCheckedOut;
			}

			@Override
			public String getComment() throws CancelledException {
				return comment;
			}

			@Override
			public boolean createKeepFile() throws CancelledException {
				return false;
			}
		};

		df.checkin(ch, false, TaskMonitor.DUMMY);
		repo.refresh();
	}

	/**
	 * Performs a check-out of the given file
	 * 
	 * @param df the domain file; cannot be null
	 * @return true if the check-out was successful
	 * @throws IOException if there is an issue checking-out the file
	 */
	public boolean checkout(DomainFile df) throws IOException {

		assertFileInProject(df);

		try {
			return df.checkout(false, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// cannot happen as long as we use the dummy
		}
		return false;
	}

	/**
	 * Performs an exclusive check-out of the given file
	 * 
	 * @param df the domain file; cannot be null
	 * @return true if the check-out was successful
	 * @throws IOException if there is an issue checking-out the file
	 */
	public boolean checkoutExclusively(DomainFile df) throws IOException {

		assertFileInProject(df);

		try {
			return df.checkout(true, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// cannot happen as long as we use the dummy
		}
		return false;
	}

	/**
	 * Deletes the given version of the given file
	 * 
	 * @param df the file; cannot be null
	 * @param version the version to delete
	 * @throws Exception if there are any exceptions deleting the given version
	 */
	public void deleteVersion(DomainFile df, int version) throws Exception {

		assertFileInProject(df);

		df.delete(version);
		repo.refresh();
	}

	/**
	 * Adds the given domain file to version control
	 * 
	 * @param df the domain file; cannot be null
	 * @param keepCheckedOut true to keep the file checked-out
	 * @throws Exception if there are any exceptions adding the file to version control
	 */
	public void addToVersionControl(DomainFile df, boolean keepCheckedOut) throws Exception {

		assertFileInProject(df);

		df.addToVersionControl("Test comment", keepCheckedOut, TaskMonitor.DUMMY);
		waitForFileSystemEvents();
	}

	/**
	 * Disposes this project.
	 * 
	 * @see FakeRepository#dispose()
	 */
	public void dispose() {
		programManager.disposeOpenPrograms();
		gProject.close();
	}

	@Override
	public String toString() {
		return gProject.getProject().getName();
	}

	// make sure the given domain file is actually in this project (this helps with copy/paste
	// errors)
	private void assertFileInProject(DomainFile df) {

		if (df == null) {
			throw new IllegalArgumentException("DomainFile cannot be null");
		}

		ProjectLocator pl = df.getProjectLocator();
		ProjectLocator mypl = getProjectFileManager().getProjectLocator();
		if (!pl.equals(mypl)) {
			throw new IllegalArgumentException("Domain file '" + df + "' is not in this project: " +
				mypl.getName() + "\nYou must call addDomainFile(filename).");
		}
	}

	private void waitForFileSystemEvents() {
		LocalFileSystem versionedFileSystem = getVersionedFileSystem();
		FileSystemEventManager eventManager =
			(FileSystemEventManager) TestUtils.getInstanceField("eventManager",
				versionedFileSystem);

		try {
			eventManager.flushEvents(DEFAULT_WAIT_TIMEOUT, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException e) {
			failWithException("Interrupted waiting for filesystem events", e);
		}
	}

	private DomainFolder getFolder(String path) throws Exception {
		Project project = getGhidraProject().getProject();
		ProjectData data = project.getProjectData();
		DomainFolder folder = data.getFolder(path);
		if (folder == null) {
			String[] parts = path.split("/");
			DomainFolder root = data.getRootFolder();
			folder = createFolders(root, parts);
		}
		return folder;
	}

	private DomainFolder createFolders(DomainFolder root, String[] parts) throws Exception {

		if (parts.length < 0) {
			throw new IllegalArgumentException("Invalid folder path");
		}

		DomainFolder folder = root;
		int start = 0;
		String first = parts[0];
		if (StringUtils.isBlank(first)) {
			start = 1; // absolute path; skip root
		}

		for (int i = start; i < parts.length; i++) {
			String name = parts[i];
			DomainFolder child = folder.getFolder(name);
			if (child == null) {
				folder = folder.createFolder(name);
			}
			else {
				folder = child;
			}
		}

		return folder;
	}

	LocalFileSystem getVersionedFileSystem() {
		ProjectFileManager fileManager = getProjectFileManager();
		LocalFileSystem fs =
			(LocalFileSystem) TestUtils.invokeInstanceMethod("getVersionedFileSystem", fileManager);
		return fs;
	}

	void refresh() {
		ProjectFileManager fileManager = getProjectFileManager();
		try {
			fileManager.refresh(true);
		}
		catch (IOException e) {
			// shouldn't happen
			throw new AssertionFailedError("Unable to refresh project " + this);
		}
	}
}
