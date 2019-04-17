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

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.Application;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.DataTypeManager;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class ArchiveRemappedHeadlessTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramDB program;

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
		assertTrue("windows_vs12_32.gdt not found", vs12ArchiveFile.isFile());
		vs9ArchiveFile = new File(win32ArchiveDir, "windows_VS9.gdt");
		vs9ArchiveFile.deleteOnExit();
		FileUtilities.copyFile(vs12ArchiveFile, vs9ArchiveFile, false, TaskMonitor.DUMMY);

		program = buildProgram();

		// Headless data type service supplied by AutoAnalysisManager
		AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
		service = analysisManager.getDataTypeManagerService();
		assertNotNull(service);
		assertNull(analysisManager.getAnalysisTool());

	}

	private ProgramDB buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY, this);
		return builder.getProgram();
	}

	@Test
	public void testGetRemappedArchive() throws Exception {

		DataTypeManager vs9dtm = service.openDataTypeArchive("windows_VS9");
		assertNotNull(vs9dtm);
		try {
			assertEquals("windows_VS9", vs9dtm.getName());
		}
		finally {
			vs9dtm.close();
		}

		// Remove archive to force use of remapping
		vs9ArchiveFile.delete();
		assertFalse("windows_VS9.gdt should not exist", vs9ArchiveFile.exists());

		DataTypeManager vs12dtm = service.openDataTypeArchive("windows_VS9");
		assertNotNull(vs12dtm);
		try {
			assertEquals("windows_vs12_32", vs12dtm.getName());
		}
		finally {
			vs12dtm.close();
		}
	}

}
