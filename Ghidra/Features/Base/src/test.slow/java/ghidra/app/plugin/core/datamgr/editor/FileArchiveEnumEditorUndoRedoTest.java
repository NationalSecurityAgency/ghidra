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

import java.io.File;
import java.io.IOException;

import org.junit.After;
import org.junit.Before;

import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.program.model.data.FileDataTypeManager;

public class FileArchiveEnumEditorUndoRedoTest extends AbstractEnumEditorUndoRedoTest {

	private File tempGdt;
	private Archive fileArchive;

	@Before
	@Override
	public void setUp() throws Exception {
		super.setUp();

		tempGdt = createTempFileForTest(".gdt");
		tempGdt.delete();

		fileArchive = plugin.getDataTypeManagerHandler().createArchive(tempGdt);

		assertTrue(fileArchive.isModifiable());

		dtm = fileArchive.getDataTypeManager();
	}

	@After
	@Override
	public void tearDown() throws Exception {
		if (fileArchive != null) {
			plugin.getDataTypeManagerHandler().closeArchive(fileArchive);
			tempGdt.delete();
		}
		super.tearDown();
	}

	@Override
	void undo() throws IOException {
		FileDataTypeManager fileDtm = (FileDataTypeManager) fileArchive.getDataTypeManager();
		fileDtm.undo();
	}

	@Override
	void redo() throws IOException {
		FileDataTypeManager fileDtm = (FileDataTypeManager) fileArchive.getDataTypeManager();
		fileDtm.redo();
	}

}
