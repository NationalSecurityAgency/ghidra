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

import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.DataTypeArchiveDB;

public class ProjectArchiveEnumEditorUndoRedoTest extends AbstractEnumEditorUndoRedoTest {

	Archive projectArchive;
	DataTypeArchiveDB dataTypeArchiveDB;

	@Before
	@Override
	public void setUp() throws Exception {
		super.setUp();

		DomainFolder rootFolder = tool.getProject().getProjectData().getRootFolder();

		dataTypeArchiveDB = new DataTypeArchiveDB(rootFolder, "Test", tool);

		projectArchive = plugin.getDataTypeManagerHandler().openArchive(dataTypeArchiveDB);

		assertTrue(projectArchive.isModifiable());

		dtm = dataTypeArchiveDB.getDataTypeManager();
	}

	@After
	@Override
	public void tearDown() throws Exception {
		if (projectArchive != null) {
			plugin.getDataTypeManagerHandler().closeArchive(projectArchive);
		}
		super.tearDown();
	}

	@Override
	void undo() throws IOException {
		dataTypeArchiveDB.undo();
	}

	@Override
	void redo() throws IOException {
		dataTypeArchiveDB.redo();
	}

}
