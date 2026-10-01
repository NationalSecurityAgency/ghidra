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
package ghidra.app.plugin.core.datamgr.editor;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.After;
import org.junit.Before;

import ghidra.app.services.Recover;
import ghidra.app.services.Upgrade;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.dtarchive.DataTypeArchiveFactory;
import ghidra.program.model.dtarchive.ProjectDataTypeArchive;
import ghidra.util.task.TaskMonitor;

public class ProjectArchiveEnumEditorUndoRedoTest extends AbstractEnumEditorUndoRedoTest {

	ProjectDataTypeArchive projectArchive;

	@Before
	@Override
	public void setUp() throws Exception {
		super.setUp();

		DomainFolder rootFolder = tool.getProject().getProjectData().getRootFolder();
		projectArchive = DataTypeArchiveFactory.createProjectArchive(rootFolder, "Test", tool);
		DomainFile domainFile = projectArchive.getDomainFile();
		projectArchive.release(tool);
		projectArchive = plugin.getArchiveManager()
				.openProjectArchive(domainFile, DomainFile.DEFAULT_VERSION, Upgrade.NO, Recover.NO,
					false, TaskMonitor.DUMMY);

		assertTrue(projectArchive.isChangeable());

		dtm = projectArchive.getDataTypeManager();
	}

	@After
	@Override
	public void tearDown() throws Exception {
		if (projectArchive != null) {
			plugin.getArchiveManager().closeArchive(projectArchive);
		}
		super.tearDown();
	}

	@Override
	void undo() throws IOException {
		projectArchive.undo();
	}

	@Override
	void redo() throws IOException {
		projectArchive.redo();
	}

}
