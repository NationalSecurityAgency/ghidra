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
import java.util.List;

import org.junit.*;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.PersistentDataTypeArchive;
import ghidra.program.model.dtarchive.DataTypeStore;
import ghidra.test.*;
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
	private ArchiveManager archiveManager;

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
		List<PersistentDataTypeArchive> dataTypeArchives = service.getDataTypeArchives();
		for (PersistentDataTypeArchive archive : dataTypeArchives) {
			service.closeArchive(archive);
		}
		archiveManager = plugin.getArchiveManager();

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
		ProgramBuilder builder = new ToyProgramBuilder();
		return builder.getProgram();
	}

	private PersistentDataTypeArchive getArchive(String achiveName) {
		for (PersistentDataTypeArchive archive : archiveManager.getOpenArchives()) {
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

	@Test
	public void testGetRemappedArchive() throws Exception {

		PersistentDataTypeArchive vs9Archive = service.openFileArchive("windows_VS9", TaskMonitor.DUMMY);
		assertNotNull(vs9Archive);
		try {
			assertEquals("windows_VS9", vs9Archive.getName());
		}
		finally {
			service.closeArchive(vs9Archive);
		}

		waitForTree(tree);// archive does NOT appear in tree

		// Remove archive to force use of remapping
		vs9ArchiveFile.delete();
		assertFalse("windows_VS9.gdt should not exist", vs9ArchiveFile.exists());

		PersistentDataTypeArchive vs12Archive = service.openFileArchive("windows_VS9", TaskMonitor.DUMMY);
		assertNotNull(vs12Archive);
		try {
			assertEquals("windows_vs12_32", vs12Archive.getName());
		}
		finally {
			service.closeArchive(vs12Archive);
		}

		waitForTree(tree);// archive does NOT appear in tree
	}

	private void close(DataTypeManager dtm) {

		runSwing(() -> {
			DataTypeStore dataStore = dtm.getDataStore();
			if (dataStore instanceof PersistentDataTypeArchive archive) {
				archiveManager.closeArchive(archive);
			}
		});
	}

	@Test
	public void testGetProgramRemappedArchive() throws Exception {

		DataTypeManager programDtm = program.getDataTypeManager();

		// Add datatype from vs9 archive into program
		// which reference to vs9 archive
		PersistentDataTypeArchive vs9Archive = service.openFileArchive("windows_VS9", TaskMonitor.DUMMY);
		assertNotNull(vs9Archive);
		int txId = program.startTransaction("Add vs9 types");
		try {
			assertEquals("windows_VS9", vs9Archive.getName());
			DataTypeManager vs9dtm = vs9Archive.getDataTypeManager();
			DataType dataType = vs9dtm.getDataType(new CategoryPath("/winnt.h"), "_PRIVILEGE_SET");
			assertNotNull("winnt.h/_PRIVILEGE_SET type not found", dataType);

			programDtm.resolve(dataType, null);

			assertNotNull(getArchive("windows_VS9"));
			assertNull(getArchive("windows_vs12"));
		}
		finally {
			program.endTransaction(txId, true);
			service.closeArchive(vs9Archive);
		}

		SourceArchive sourceArchive = getSourceArchive(programDtm, "windows_VS9");
		assertNotNull(sourceArchive);

		DataTypeManager archiveDtm = archiveManager.getDataTypeManager(sourceArchive);
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

		archiveDtm = archiveManager.getDataTypeManager(sourceArchive);
		assertNotNull(archiveDtm);
		assertEquals("windows_vs12_32", archiveDtm.getName());

		ArchiveRootNode archiveRootNode = (ArchiveRootNode) tree.getModelRoot();
		DataTypeStoreNode archiveNode =
			(DataTypeStoreNode) archiveRootNode.getChild("windows_vs12_32");
		assertNotNull(archiveNode);
		DataTypeStoreNode programNode =
			(DataTypeStoreNode) archiveRootNode.getChild(program.getName());
		assertNotNull(programNode);

		List<SourceArchive> archives = program.getDataTypeManager().getSourceArchives();
		assertEquals(1, archives.size());
		assertEquals("windows_vs12_32", archives.get(0).getName());

	}
}
