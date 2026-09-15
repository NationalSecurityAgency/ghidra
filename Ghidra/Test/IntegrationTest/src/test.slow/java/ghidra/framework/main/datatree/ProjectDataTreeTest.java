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
package ghidra.framework.main.datatree;

import static org.junit.Assert.*;

import java.util.function.BooleanSupplier;

import org.junit.*;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.data.FolderLinkContentHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramLinkContentHandler;
import ghidra.program.model.listing.Program;
import ghidra.test.*;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

public class ProjectDataTreeTest extends AbstractGhidraHeadedIntegrationTest {

	private FrontEndTestEnv env;

	private DomainFile programAFile;

	private Program program;

	@Before
	public void setUp() throws Exception {
		env = new FrontEndTestEnv();
		program = ToyProgramBuilder.buildSimpleProgram("foo", this);

		DomainFolder rootFolder = env.getRootFolder();
		programAFile = rootFolder.getFile("Program_A");
		assertNotNull(programAFile);
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.release(this);
		}
		env.dispose();
	}

	@Test
	public void testLinkFileUpdate() throws Exception {

		GTree tree = env.getTree();
		GTreeNode modelRoot = tree.getModelRoot();
		DomainFolder rootFolder = env.getRootFolder();

		DomainFolder aFolder = rootFolder.createFolder("A");

		// file link created before referenced file
		aFolder.createLinkFile(rootFolder.getProjectData(), "/A/x", true, "y",
			ProgramLinkContentHandler.INSTANCE);

		rootFolder.createLinkFile(rootFolder.getProjectData(), "/A", false, "B",
			FolderLinkContentHandler.INSTANCE);

		env.waitForTree();

		Swing.runNow(() -> tree.expandPath(modelRoot.getChild("A")));
		env.waitForTree();

		Swing.runNow(() -> tree.expandPath(modelRoot.getChild("B")));
		env.waitForTree();

		// Add file 'x' while folder A and linked-folder B are both expanded
		aFolder.createFile("x", program, TaskMonitor.DUMMY);
		program.release(this);
		program = null;

		env.waitForTree();

		//
		// 	Verify good state after everything created
		// 	
		//	/A
		//		x
		//		y -> x
		//	/B -> /A  (linked-folder)
		//		x
		//		y -> x
		//

		DomainFolderNode aFolderNode = (DomainFolderNode) modelRoot.getChild("A");
		DomainFileNode xNode = (DomainFileNode) aFolderNode.getChild("x");
		assertNotNull(xNode);

		DomainFileNode yNode = (DomainFileNode) aFolderNode.getChild("y");
		assertNotNull(yNode);
		waitForRefresh(yNode);

		String tip = yNode.getToolTip();
		assertFalse(tip.contains("Broken"));

		xNode = (DomainFileNode) aFolderNode.getChild("x");
		assertNotNull(xNode);

		DomainFileNode bFolderLinkNode = (DomainFileNode) modelRoot.getChild("B");
		yNode = (DomainFileNode) bFolderLinkNode.getChild("y");
		assertNotNull(yNode);
		waitForRefresh(yNode);

		tip = yNode.getToolTip();
		assertFalse(tip.contains("Broken"));

		// Remove 'x' file and verify broken links are reflected

		xNode = (DomainFileNode) aFolderNode.getChild("x");
		xNode.getDomainFile().delete();

		env.waitForTree();

		assertNull(aFolderNode.getChild("x"));

		yNode = (DomainFileNode) aFolderNode.getChild("y");
		assertNotNull(yNode);
		waitForRefresh(yNode);

		tip = yNode.getToolTip();
		assertTrue(tip.contains("Broken"));

		xNode = (DomainFileNode) aFolderNode.getChild("x");
		assertNull(xNode);

		yNode = (DomainFileNode) bFolderLinkNode.getChild("y");
		assertNotNull(yNode);
		waitForRefresh(yNode);

		tip = yNode.getToolTip();
		assertTrue(tip.contains("Broken"));

	}

	@Test
	public void testLinkFileUpdate1() throws Exception {

		GTree tree = env.getTree();
		GTreeNode modelRoot = tree.getModelRoot();
		DomainFolder rootFolder = env.getRootFolder();

		DomainFolder aFolder = rootFolder.createFolder("A");

		// file link created before referenced file
		aFolder.createLinkFile(rootFolder.getProjectData(), "/A/x", true, "y",
			ProgramLinkContentHandler.INSTANCE);

		env.waitForTree();

		Swing.runNow(() -> tree.expandPath(modelRoot.getChild("A")));
		env.waitForTree();

		// Add file 'x' before folder A and is expanded and linked-folder B is not
		aFolder.createFile("x", program, TaskMonitor.DUMMY);
		program.release(this);
		program = null;

		env.waitForTree();

		rootFolder.createLinkFile(rootFolder.getProjectData(), "/A", false, "B",
			FolderLinkContentHandler.INSTANCE);
		env.waitForTree();

		DomainFileNode bFolderLinkNode = (DomainFileNode) modelRoot.getChild("B");
		Swing.runNow(() -> tree.expandPath(bFolderLinkNode));
		env.waitForTree();

		//
		// 	Verify good state after everything created
		// 	
		//	/A
		//		x
		//		y -> x
		//	/B -> /A  (linked-folder)
		//		x
		//		y -> x
		//

		DomainFolderNode aFolderNode = (DomainFolderNode) modelRoot.getChild("A");
		DomainFileNode xNode = (DomainFileNode) aFolderNode.getChild("x");
		assertNotNull(xNode);

		DomainFileNode yNode = (DomainFileNode) aFolderNode.getChild("y");
		assertNotNull(yNode);
		waitForRefresh(yNode);

		String tip = yNode.getToolTip();
		assertFalse(tip.contains("Broken"));

		xNode = (DomainFileNode) aFolderNode.getChild("x");
		assertNotNull(xNode);

		yNode = (DomainFileNode) bFolderLinkNode.getChild("y");
		assertNotNull(yNode);
		waitForRefresh(yNode);

		tip = yNode.getToolTip();
		assertFalse(tip.contains("Broken"));

		// Remove 'x' file and verify broken links are reflected

		xNode = (DomainFileNode) aFolderNode.getChild("x");
		assertNotNull(xNode);

		xNode.getDomainFile().delete();

		env.waitForTree();

		assertNull(aFolderNode.getChild("x"));

		yNode = (DomainFileNode) aFolderNode.getChild("y");
		assertNotNull(yNode);
		waitForRefresh(yNode);

		tip = yNode.getToolTip();
		assertTrue(tip.contains("Broken"));

		xNode = (DomainFileNode) aFolderNode.getChild("x");
		assertNull(xNode);

		yNode = (DomainFileNode) bFolderLinkNode.getChild("y");
		assertNotNull(yNode);
		waitForRefresh(yNode);

		tip = yNode.getToolTip();
		assertTrue(tip.contains("Broken"));

	}

	@Test
	public void testLinkFileUpdate2() throws Exception {

		GTree tree = env.getTree();
		GTreeNode modelRoot = tree.getModelRoot();
		DomainFolder rootFolder = env.getRootFolder();

		DomainFolder aFolder = rootFolder.createFolder("A");

		// file link created before referenced file
		aFolder.createLinkFile(rootFolder.getProjectData(), "/A/x", true, "y",
			ProgramLinkContentHandler.INSTANCE);

		rootFolder.createLinkFile(rootFolder.getProjectData(), "/A", false, "B",
			FolderLinkContentHandler.INSTANCE);
		env.waitForTree();

		DomainFileNode bFolderLinkNode = (DomainFileNode) modelRoot.getChild("B");
		Swing.runNow(() -> tree.expandPath(bFolderLinkNode));
		env.waitForTree();

		// Add file 'x' while linked-folder B is expanded and folder A is not
		DomainFile xFile = aFolder.createFile("x", program, TaskMonitor.DUMMY);
		program.release(this);
		program = null;
		env.waitForTree();

		//// Verify good state after everything created (leave A collapsed)

		DomainFileNode xNode = (DomainFileNode) bFolderLinkNode.getChild("x");
		assertNotNull(xNode);

		DomainFileNode yNode = (DomainFileNode) bFolderLinkNode.getChild("y");
		assertNotNull(yNode);
		waitForRefresh(yNode);

		String tip = yNode.getToolTip();
		assertFalse(tip.contains("Broken"));

		//// Remove 'x' file

		xFile.delete();

		env.waitForTree();

		assertNull(bFolderLinkNode.getChild("x"));

		yNode = (DomainFileNode) bFolderLinkNode.getChild("y");
		assertNotNull(yNode);
		waitForRefresh(yNode);

		tip = yNode.getToolTip();
		assertTrue(tip.contains("Broken"));

	}

	@Test
	public void testLinkFileUpdate3() throws Exception {

		GTree tree = env.getTree();
		GTreeNode modelRoot = tree.getModelRoot();
		DomainFolder rootFolder = env.getRootFolder();

		rootFolder.createLinkFile(rootFolder.getProjectData(), "/usr/bin", false, "bin",
			FolderLinkContentHandler.INSTANCE);

		DomainFolder usrBinFolder = rootFolder.createFolder("usr").createFolder("bin");

		env.waitForTree();

		Swing.runNow(() -> tree.expandPath(modelRoot.getChild("usr")));
		env.waitForTree();

		Swing.runNow(() -> tree.expandPath(modelRoot.getChild("usr").getChild("bin")));
		env.waitForTree();

		Swing.runNow(() -> tree.expandPath(modelRoot.getChild("bin")));
		env.waitForTree();

		// Add file 'bash' 
		DomainFile bashFile = usrBinFolder.createFile("bash", program, TaskMonitor.DUMMY);
		program.release(this);
		program = null;
		env.waitForTree();

		DomainFileNode binFolderLinkNode = (DomainFileNode) modelRoot.getChild("bin");
		assertNotNull(binFolderLinkNode.getChild("bash"));

		// 	
		//	/bin -> /usr/bin (linked folder)
		//		bash
		//	/usr
		//		/bin
		//			bash
		//

		// Delete real folders and content
		bashFile.delete();
		usrBinFolder.delete(); // /usr/bin
		rootFolder.getFolder("usr").delete();

		env.waitForTree();

		assertNull(binFolderLinkNode.getChild("bash"));

		waitForRefresh(binFolderLinkNode);
		env.waitForTree();

		String tip = binFolderLinkNode.getToolTip();
		assertTrue(tip.contains("Broken"));

//		binLinkFile.delete();
		env.waitForTree();

		// Re-create content

		rootFolder.createLinkFile(rootFolder.getProjectData(), "/usr/bin", false, "bin",
			FolderLinkContentHandler.INSTANCE);

		usrBinFolder = rootFolder.createFolder("usr").createFolder("bin");

		env.waitForTree();

		Swing.runNow(() -> tree.expandPath(modelRoot.getChild("usr")));
		env.waitForTree();

		Swing.runNow(() -> tree.expandPath(modelRoot.getChild("usr").getChild("bin")));
		env.waitForTree();

		Swing.runNow(() -> tree.expandPath(modelRoot.getChild("bin")));
		env.waitForTree();

		program = (Program) programAFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
		assertNotNull(program);
		usrBinFolder.createFile("bash", program, TaskMonitor.DUMMY);
		program.release(this);
		program = null;

		env.waitForTree();

		DomainFileNode xLinkedFileNode = (DomainFileNode) binFolderLinkNode.getChild("bash");
		assertNotNull(xLinkedFileNode);

		tip = binFolderLinkNode.getToolTip();
		assertFalse(tip.contains("Broken"));

		// Repeat removal of folder A and its contents
		bashFile = usrBinFolder.getFile("bash");
		assertNotNull(bashFile);
		bashFile.delete();
		usrBinFolder.delete();
		rootFolder.getFolder("usr").delete();

		env.waitForTree();

		assertNull(binFolderLinkNode.getChild("bash"));

		waitForRefresh(binFolderLinkNode);
		env.waitForTree();

		tip = binFolderLinkNode.getToolTip();
		assertTrue(tip.contains("Broken"));
	}

	private void waitForRefresh(DomainFileNode fileNode) {
		waitFor(new BooleanSupplier() {
			@Override
			public boolean getAsBoolean() {
				return !fileNode.hasPendingRefresh();
			}
		});
	}
}
