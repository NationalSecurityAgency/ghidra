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

import static org.junit.Assert.*;

import java.io.File;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.datamgr.actions.UpdateSourceArchiveNamesAction;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class ArchiveRemappedHeadedTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private ProgramDB program;
	private DataTypeManagerPlugin plugin;
	private DataTypesProvider provider;
	private DataTypeArchiveGTree tree;

	private DataTypeManagerService service;

	private File win32ArchiveDir;
	private File vs12ArchiveFile;
	private File vs9ArchiveFile;

	@Before
	public void setUp() throws Exception {

		// Create windows_VS9 archive copy before DataTypeManagerHandler initializes 
		// static list of known archives
		win32ArchiveDir =
			Application.getModuleDataSubDirectory("Base", "typeinfo/win32").getFile(false);
		assertNotNull(win32ArchiveDir);
		vs12ArchiveFile = new File(win32ArchiveDir, "windows_vs12_32.gdt");
		assertTrue("windows_vs12.gdt not found", vs12ArchiveFile.isFile());
		vs9ArchiveFile = new File(win32ArchiveDir, "windows_VS9.gdt");
		vs9ArchiveFile.deleteOnExit();
		FileUtilities.copyFile(vs12ArchiveFile, vs9ArchiveFile, false, TaskMonitor.DUMMY);

		env = new TestEnv();
		tool = env.getTool();
		setErrorGUIEnabled(false);
		tool.addPlugin(CodeBrowserPlugin.class.getName());

		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		plugin = env.getPlugin(DataTypeManagerPlugin.class);
		service = tool.getService(DataTypeManagerService.class);
		assertNotNull(service);

		// Close any archives which may have opened with tool
		for (DataTypeManager dtm : service.getDataTypeManagers()) {
			System.out.println("Closing " + dtm.getName());
			dtm.close();
		}

		program = buildProgram();

		env.showTool();

		provider = plugin.getProvider();
		tool.showComponentProvider(provider, true);

		tree = provider.getGTree();
		waitForTree(tree);
	}

	@After
	public void tearDown() {
		if (env != null) {
			env.dispose();
		}
	}

	private void openProgramInTool() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		waitForTree(tree);
	}

	private ProgramDB buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY, this);
		return builder.getProgram();
	}

	private Archive getArchive(DataTypeManager dtm) {
		DataTypeManagerHandler dtmHandler = plugin.getDataTypeManagerHandler();
		for (Archive archive : dtmHandler.getAllArchives()) {
			if (dtm == archive.getDataTypeManager()) {
				return archive;
			}
		}
		return null;
	}

	private Archive getArchive(String achiveName) {
		DataTypeManagerHandler dtmHandler = plugin.getDataTypeManagerHandler();
		for (Archive archive : dtmHandler.getAllArchives()) {
			if (achiveName.equals(archive.getName())) {
				return archive;
			}
		}
		return null;
	}

	private SourceArchive getSourceArchive(DataTypeManager dtm, String name) {
		for (SourceArchive archive : dtm.getSourceArchives()) {
			if (name.equals(archive.getName())) {
				return archive;
			}
		}
		return null;
	}

	private ActionContext createContext(GTreeNode node) {
		return new DataTypesActionContext(provider, program, tree, node);
	}

	@Test
	public void testGetRemappedArchive() throws Exception {

		DataTypeManager vs9dtm = service.openDataTypeArchive("windows_VS9");
		assertNotNull(vs9dtm);
		try {
			assertEquals("windows_VS9", vs9dtm.getName());
		}
		finally {
			close(vs9dtm);
		}

		waitForTree(tree);// archive does NOT appear in tree

		// Remove archive to force use of remapping
		vs9ArchiveFile.delete();
		assertFalse("windows_VS9.gdt should not exist", vs9ArchiveFile.exists());

		DataTypeManager vs12dtm = service.openDataTypeArchive("windows_VS9");
		assertNotNull(vs12dtm);
		try {
			assertEquals("windows_vs12_32", vs12dtm.getName());
		}
		finally {
			close(vs12dtm);
		}

		waitForTree(tree);// archive does NOT appear in tree
	}

	private void close(DataTypeManager dtm) {
		runSwing(() -> getArchive(dtm).close());
	}

	@Test
	public void testGetProgramRemappedArchive() throws Exception {

		DataTypeManagerHandler handler = plugin.getDataTypeManagerHandler();

		DataTypeManager programDtm = program.getDataTypeManager();

		// Add datatype from vs9 archive into program
		// which reference to vs9 archive
		DataTypeManager vs9dtm = service.openDataTypeArchive("windows_VS9");
		assertNotNull(vs9dtm);
		int txId = program.startTransaction("Add vs9 types");
		try {
			assertEquals("windows_VS9", vs9dtm.getName());

			DataType dataType = vs9dtm.getDataType(new CategoryPath("/winnt.h"), "_PRIVILEGE_SET");
			assertNotNull("winnt.h/_PRIVILEGE_SET type not found", dataType);

			programDtm.resolve(dataType, null);

			assertNotNull(getArchive("windows_VS9"));
			assertNull(getArchive("windows_vs12"));
		}
		finally {
			program.endTransaction(txId, true);
			close(vs9dtm);
		}

		SourceArchive sourceArchive = getSourceArchive(programDtm, "windows_VS9");
		assertNotNull(sourceArchive);

		DataTypeManager archiveDtm = handler.getDataTypeManager(sourceArchive);
		assertNull(archiveDtm);// archive not yet opened

		// Remove archive to force use of re-mapping
		vs9ArchiveFile.delete();
		assertFalse("windows_VS9.gdt should not exist", vs9ArchiveFile.exists());

		// open program in tool and ensure that remapped vs12 archive
		// is opened in place of vs9 archive
		openProgramInTool();

		waitForTree(tree);

		assertNull(getArchive("windows_VS9"));
		assertNull(getArchive("windows_vs12"));
		assertNotNull(getArchive("windows_vs12_32"));

		archiveDtm = handler.getDataTypeManager(sourceArchive);
		assertNotNull(archiveDtm);
		assertEquals("windows_vs12_32", archiveDtm.getName());

		ArchiveRootNode archiveRootNode = (ArchiveRootNode) tree.getModelRoot();
		ArchiveNode archiveNode = (ArchiveNode) archiveRootNode.getChild("windows_vs12_32");
		assertNotNull(archiveNode);
		ArchiveNode programNode = (ArchiveNode) archiveRootNode.getChild(program.getName());
		assertNotNull(programNode);

		// Popup action instantiated on-the-fly and does not persist within tool
		DockingActionIf updateSourceArchiveNameActionForProgram =
			new UpdateSourceArchiveNamesAction(plugin, programDtm);
		assertTrue(updateSourceArchiveNameActionForProgram.isEnabledForContext(
			createContext(programNode)));
		DockingActionIf updateSourceArchiveNameActionForArchive =
			new UpdateSourceArchiveNamesAction(plugin, archiveDtm);
		assertFalse(updateSourceArchiveNameActionForArchive.isEnabledForContext(
			createContext(programNode)));

		updateSourceArchiveNameActionForProgram.actionPerformed(null);// action does not rely on context - relies on construction instead

		assertFalse(updateSourceArchiveNameActionForProgram.isEnabledForContext(
			createContext(programNode)));
		assertFalse(updateSourceArchiveNameActionForArchive.isEnabledForContext(
			createContext(programNode)));

	}
}
