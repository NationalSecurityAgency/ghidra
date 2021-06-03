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
package ghidra.app.plugin.core.datamgr;

import java.io.File;
import java.io.IOException;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class DataTypeTestUtils {

	private static final String ARCHIVE_FILE_EXTENSION = FileDataTypeManager.SUFFIX;
	private static File tempArchiveDir;
	static DataTypeArchiveGTree archiveTree;

	private DataTypeTestUtils() {
		// utils class
	}

	private static File getTempDir() throws IOException {
		if (tempArchiveDir == null) {
			tempArchiveDir = AbstractGenericTest.createTempDirectory("archive.db.dir");
		}
		return tempArchiveDir;
	}

	// copies the default test archive into a local version
	public static File createArchive(String filename) throws Exception {
		return createLocalArchiveFromExistingArchive(filename, "TestArchive.gdt");
	}

	// copies the archive from the given filename to a local version
	public static File copyArchive(String filename) throws Exception {
		return createLocalArchiveFromExistingArchive(filename, filename);
	}

	private static File createLocalArchiveFromExistingArchive(String filename,
			String existingFilename) throws Exception {

		File tempDir = getTempDir();
		File scratchFile = new File(tempDir, filename);
		if (scratchFile.exists()) {
			scratchFile.delete();
		}

		File packedDbFile = AbstractGenericTest.getTestDataFile(existingFilename);
		if (packedDbFile == null) {
			Msg.debug(DataTypeTestUtils.class,
				"No packed DB file named '" + existingFilename + "'");
			return null;
		}

		// copy the archive DB file to avoid lock contention in parallel testing
		File tempDbFile = new File(tempDir, "copy." + existingFilename);
		tempDbFile.deleteOnExit();
		FileUtilities.copyFile(packedDbFile, tempDbFile, false, TaskMonitor.DUMMY);

		boolean openForUpdate = true; // open for update to allow auto-upgrade to occur if needed
		FileDataTypeManager fm = FileDataTypeManager.openFileArchive(tempDbFile, openForUpdate);
		fm.saveAs(scratchFile);
		fm.close();

		Msg.debug(DataTypeTestUtils.class, "Created test archive: " + scratchFile);

		return scratchFile;
	}

	public static ArchiveNode openArchive(String archiveDirPath, String archiveName,
			boolean checkout, DataTypeManagerPlugin plugin) throws Exception {

		File file = new File(archiveDirPath, archiveName);
		DataTypeManagerHandler dataTypeManagerHandler = plugin.getDataTypeManagerHandler();

		// this opens the archive and triggers the tree to rebuild
		dataTypeManagerHandler.openArchive(file, checkout, false);
		waitForTree(plugin);

		GTree tree = plugin.getProvider().getGTree();
		GTreeNode rootNode = tree.getModelRoot();
		return (ArchiveNode) rootNode.getChild(trimFullArchiveName(archiveName));
	}

	public static ArchiveNode openArchive(String archiveName, boolean checkout,
			DataTypeManagerPlugin plugin) throws Exception {
		ArchiveNode openArchive = openArchive(archiveName, checkout, false, plugin);
		waitForTree(plugin);
		return openArchive;
	}

	private static void waitForTree(DataTypeManagerPlugin plugin) {
		GTree tree = plugin.getProvider().getGTree();
		while (tree.isBusy()) {
			try {
				Thread.sleep(50);
			}
			catch (Exception e) {
				// who cares?
			}
		}
		AbstractGenericTest.waitForPostedSwingRunnables();
	}

	public static ArchiveNode openArchive(String archiveName, boolean checkout,
			boolean isUserAction, DataTypeManagerPlugin plugin) throws Exception {

		File tempDir = getTempDir();
		File file = new File(tempDir, archiveName);
		DataTypeManagerHandler dataTypeManagerHandler = plugin.getDataTypeManagerHandler();

		// this opens the archive and triggers the tree to rebuild
		dataTypeManagerHandler.openArchive(file, checkout, isUserAction);

		archiveTree = plugin.getProvider().getGTree();
		GTreeNode rootNode = archiveTree.getViewRoot();
		waitForTree(plugin);
		return (ArchiveNode) rootNode.getChild(trimFullArchiveName(archiveName));
	}

	public static void closeArchive(final ArchiveNode archiveNode, final boolean deleteFile)
			throws Exception {

		Exception exception = Swing.runNow(() -> {
			try {
				doCloseArchive(archiveNode, deleteFile);
				return null;
			}
			catch (Exception e) {
				return e;
			}
		});

		if (exception != null) {
			throw new RuntimeException("Exception closing archive on Swing thread!: ", exception);
		}
	}

	private static void doCloseArchive(ArchiveNode archiveNode, boolean deleteFile)
			throws Exception {

		if (archiveNode == null) {
			return;
		}

		Archive archive = archiveNode.getArchive();
		File file = null;
		if ((archive instanceof FileArchive) && deleteFile) {
			file = ((FileArchive) archive).getFile().getFile(false);
		}

		archiveNode.getArchive().close();

		if (file != null) {
			FileDataTypeManager.delete(file);
		}
	}

	/**
	 * Checks out the archive by the given name.
	 *
	 * @param archiveName The name of the archive to open.  This must be a child off of the root node.
	 * @param plugin The plugin that contains the tree and actions under test
	 * @return The archive node associated with the open archive
	 * @throws Exception If there is any problem finding or opening the archive for the given name
	 */
	public static ArchiveNode checkOutArchive(String archiveName,
			final DataTypeManagerPlugin plugin) throws Exception {

		String archiveNodeName = trimFullArchiveName(archiveName);
		GTree tree = plugin.getProvider().getGTree();
		GTreeNode rootNode = tree.getModelRoot();
		ArchiveNode archiveNode = (ArchiveNode) rootNode.getChild(archiveNodeName);
		if (archiveNode == null) {
			throw new IllegalArgumentException(
				"Unable to locate an archive by the name: " + archiveNodeName);
		}

		ArchiveUtils.lockArchive((FileArchive) archiveNode.getArchive());

		// checking out the archive causes the trees nodes to be recreated
		return (ArchiveNode) rootNode.getChild(archiveNodeName);
	}

	/**
	 * Trims the given string if it ends with {@link #ARCHIVE_FILE_EXTENSION}.
	 * @param archiveName The name to trim
	 * @return The original name, trimmed as necessary
	 */
	private static String trimFullArchiveName(String archiveName) {
		if (archiveName.endsWith(ARCHIVE_FILE_EXTENSION)) {
			int endIndex = archiveName.indexOf(ARCHIVE_FILE_EXTENSION);
			return archiveName.substring(0, endIndex);
		}
		return archiveName;
	}

	public static ArchiveNode createOpenAndCheckoutArchive(String archiveName,
			DataTypeManagerPlugin plugin) throws Exception {
		createArchive(archiveName);
		return openArchive(archiveName, true, plugin);
	}

	public static ArchiveNode copyOpenAndCheckoutArchive(String archiveName,
			DataTypeManagerPlugin plugin) throws Exception {
		copyArchive(archiveName);
		return openArchive(archiveName, true, plugin);
	}

	public static void performAction(DockingActionIf action, Program program, GTree tree) {
		performAction(action, program, tree, true);
	}

	public static void performAction(DockingActionIf action, Program program, GTree tree,
			boolean wait) {
		AbstractGenericTest.runSwing(() -> {
			ActionContext context =
				new DataTypesActionContext(null, program, (DataTypeArchiveGTree) tree, null, true);
			action.actionPerformed(context);
		}, wait);

		if (!SwingUtilities.isEventDispatchThread()) {
			AbstractGenericTest.waitForSwing();
		}
	}

	public static void performAction(DockingActionIf action, GTree tree) {
		performAction(action, tree, true);
	}

	public static void performAction(DockingActionIf action, GTree tree, boolean wait) {
		AbstractGenericTest.runSwing(() -> {
			ActionContext context =
				new DataTypesActionContext(null, null, (DataTypeArchiveGTree) tree, null, true);
			action.actionPerformed(context);
		}, wait);

		if (!SwingUtilities.isEventDispatchThread()) {
			AbstractGenericTest.waitForSwing();
		}
	}

	public static void createCategory(Category parent, String categoryName) throws Exception {
		DataTypeManager dtm = parent.getDataTypeManager();
		int id = dtm.startTransaction("create category");
		try {
			parent.createCategory(categoryName);
		}
		finally {
			dtm.endTransaction(id, true);
		}

	}

}
