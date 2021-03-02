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
package ghidra.app.plugin.core.debug.service.url;

import static org.junit.Assert.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Deque;
import java.util.LinkedList;

import org.junit.*;

import ghidra.base.project.GhidraProject;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;
import ghidra.test.*;
import ghidra.util.Msg;
import ghidra.util.exception.FileInUseException;
import ghidra.util.task.ConsoleTaskMonitor;

@Ignore("Not actual tests")
public class ProjectExperimentsTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;

	protected static String obj(Object obj) {
		return String.format("%s(%08x)", obj, System.identityHashCode(obj));
	}

	public static abstract class AbstractRecordingListener {
		private final Deque<String> log = new LinkedList<>();

		public synchronized void clear() {
			log.clear();
		}

		protected synchronized void log(String msg) {
			Msg.info(this, msg);
			log.add(msg);
		}

		public synchronized String poll() {
			return log.poll();
		}

		public void ignore(int count) {
			for (int i = 0; i < count; i++) {
				waitForValue(this::poll);
			}
		}
	}

	public static class RecordingProjectListener extends AbstractRecordingListener
			implements ProjectListener {

		@Override
		public void projectOpened(Project project) {
			log("Project opened: " + project);
		}

		@Override
		public void projectClosed(Project project) {
			log("Project closed: " + project);
		}
	}

	public static class RecordingDomainFolderListener extends AbstractRecordingListener
			implements DomainFolderChangeListener {

		@Override
		public void domainFolderAdded(DomainFolder folder) {
			log("Folder added: folder=" + folder);
		}

		@Override
		public void domainFileAdded(DomainFile file) {
			log("File added: file=" + file);
		}

		@Override
		public void domainFolderRemoved(DomainFolder parent, String name) {
			log("Folder removed: parent=" + parent + " name=" + name);
		}

		@Override
		public void domainFileRemoved(DomainFolder parent, String name, String fileID) {
			log("File removed: parent=" + parent + " name=" + name + " id=" + fileID);
		}

		@Override
		public void domainFolderRenamed(DomainFolder folder, String oldName) {
			log("Folder renamed: folder=" + folder + " oldName=" + oldName);
		}

		@Override
		public void domainFileRenamed(DomainFile file, String oldName) {
			log("File renamed: file=" + file + " oldName=" + oldName);
		}

		@Override
		public void domainFolderMoved(DomainFolder folder, DomainFolder oldParent) {
			log("Folder moved: folder=" + folder + " oldParent=" + oldParent);
		}

		@Override
		public void domainFileMoved(DomainFile file, DomainFolder oldParent, String oldName) {
			log("File moved: file=" + file + " oldParent=" + oldParent + " oldName=" + oldName);
		}

		@Override
		public void domainFolderSetActive(DomainFolder folder) {
			log("File set active: folder=" + folder);
		}

		@Override
		public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
			log("File status changed: file=" + file + " idSet=" + fileIDset);
		}

		@Override
		public void domainFileObjectReplaced(DomainFile file, DomainObject oldObject) {
			log("File object replaced: file=" + file + " oldObject=" + obj(oldObject));
		}

		@Override
		public void domainFileObjectOpenedForUpdate(DomainFile file, DomainObject object) {
			log("File object opened for update: file=" + file + " object=" + obj(object));
		}

		@Override
		public void domainFileObjectClosed(DomainFile file, DomainObject object) {
			log("File object closed: file=" + file + " object=" + obj(object));
		}
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testCloseThenOpenProject() throws Exception {
		RecordingProjectListener rpl = new RecordingProjectListener();
		FrontEndTool fet = env.getFrontEndTool();
		fet.addProjectListener(rpl);
		ProjectManager pm = fet.getProjectManager();
		Project proj1 = pm.getActiveProject();
		ProjectLocator loc1 = proj1.getProjectLocator();

		Path temp = Files.createTempDirectory("ghidra");
		GhidraProject gp2 = GhidraProject.createProject(temp.toString(), "proj2", true);
		Project proj2 = gp2.getProject();
		ProjectLocator loc2 = proj2.getProjectLocator();

		proj1.close();
		proj2.close();

		assertNotNull(proj2 = pm.openProject(loc2, false, false));

		ProjectData data1 = proj2.addProjectView(loc1.getURL());
		assertNotNull(data1);

		// It's a cryin' shame. I don't get *any* callbacks. _ANY!_
		assertNull(rpl.poll());
	}

	@Test
	@Ignore("Just an experiment, anyway. Dev -> Batch, in actual nightly tests")
	public void testCreateProgramFile() throws Exception {
		RecordingDomainFolderListener rdfl = new RecordingDomainFolderListener();
		ProjectData data = env.getProject().getProjectData();
		data.addDomainFolderChangeListener(rdfl);

		ToyProgramBuilder b = new ToyProgramBuilder("test", true);
		Program program = b.getProgram();
		data.getRootFolder().createFile(program.getName(), program, new ConsoleTaskMonitor());

		assertEquals("File object closed: file=/test object=" + obj(program),
			waitForValue(rdfl::poll));
		assertEquals("File object opened for update: file=ghidra_DevTestProject:/test object=" +
			obj(program), waitForValue(rdfl::poll));
	}

	@Test
	public void testRenameOpenProgramFile() throws Exception {
		RecordingDomainFolderListener rdfl = new RecordingDomainFolderListener();
		ProjectData data = env.getProject().getProjectData();
		data.addDomainFolderChangeListener(rdfl);

		ToyProgramBuilder b = new ToyProgramBuilder("test", true);
		Program program = b.getProgram();
		DomainFolder myFolder = data.getRootFolder().createFolder("MyFolder");
		DomainFile file = myFolder.createFile(program.getName(), program, new ConsoleTaskMonitor());
		rdfl.ignore(2);

		try {
			file.setName("changed");
			fail();
		}
		catch (FileInUseException e) {
			// Excellent
			Msg.info(this, e.getMessage());
		}
	}

	@Test
	public void testRenameFolderContainingOpenProgramFile() throws Exception {
		RecordingDomainFolderListener rdfl = new RecordingDomainFolderListener();
		ProjectData data = env.getProject().getProjectData();
		data.addDomainFolderChangeListener(rdfl);

		ToyProgramBuilder b = new ToyProgramBuilder("test", true);
		Program program = b.getProgram();
		DomainFolder myFolder = data.getRootFolder().createFolder("MyFolder");
		myFolder.createFile(program.getName(), program, new ConsoleTaskMonitor());
		rdfl.ignore(2);

		try {
			myFolder.setName("YourFolder");
			fail();
		}
		catch (FileInUseException e) {
			// Excellent
			Msg.info(this, e.getMessage());
		}
	}
}
