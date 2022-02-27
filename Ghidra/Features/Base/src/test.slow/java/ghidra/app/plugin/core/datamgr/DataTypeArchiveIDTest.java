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

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;

import org.junit.Test;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.framework.Application;
import ghidra.program.model.data.*;

public class DataTypeArchiveIDTest extends AbstractGenericTest {

	private static final String WIN_VS12_32_GDT_PATH = "typeinfo/win32/windows_vs12_32.gdt";
	private static final String WIN_VS12_64_GDT_PATH = "typeinfo/win32/windows_vs12_64.gdt";
	private static final String GENERIC_CLIB_32_GDT_PATH = "typeinfo/generic/generic_clib.gdt";
	private static final String GENERIC_CLIB_64_GDT_PATH = "typeinfo/generic/generic_clib_64.gdt";
	private static final String MAC_OS_10_9_GDT_PATH = "typeinfo/mac_10.9/mac_osx.gdt";

	private static final HashMap<String, String> archiveIdMap = new HashMap<>();
	static {
		archiveIdMap.put(WIN_VS12_32_GDT_PATH, "2644092282468053077");
		archiveIdMap.put(WIN_VS12_64_GDT_PATH, "3193696833254024484");
		archiveIdMap.put(GENERIC_CLIB_32_GDT_PATH, "2644097909188870631");
		archiveIdMap.put(GENERIC_CLIB_64_GDT_PATH, "3193699959493190971");
		archiveIdMap.put(MAC_OS_10_9_GDT_PATH, "2650667045259492112");
	}

	@Test
	public void testArchiveIDMatch() throws IOException {

		HashSet<String> notFound = new HashSet<>(archiveIdMap.keySet());

		for (ResourceFile gdtFile : Application.findFilesByExtensionInApplication(".gdt")) {

			String path = gdtFile.getAbsolutePath();
			if (!path.contains("/data/typeinfo/")) {
				continue; // only verify standard archives
			}

			int ix = path.indexOf("/typeinfo/");
			path = path.substring(ix + 1); // path starts with typeinfo/...

			String oldID = archiveIdMap.get(path);
			if (oldID == null) {
				fail("New archive added, test must be updated: " + path);
			}

			notFound.remove(path);

			FileDataTypeManager dtm = FileDataTypeManager.openFileArchive(gdtFile, false);
			try {
				assertEquals("Archive UniversalID mismatch: " + path, oldID,
					dtm.getUniversalID().toString());
			}
			finally {
				dtm.close();
			}
		}

		if (!notFound.isEmpty()) {
			System.out.println("The following standard archives were not found:");
			for (String p : notFound) {
				System.out.println("missing archive: " + p);
			}
			fail("One or more standard archives are missing");
		}

	}

	private void verifyArchive(DataType dt, String gdtPath) {
		SourceArchive sourceArchive = dt.getSourceArchive();
		assertEquals(archiveIdMap.get(gdtPath), sourceArchive.getSourceArchiveID().toString());
		int ix = gdtPath.lastIndexOf('/');
		String gdtName = gdtPath.substring(ix + 1);
		ix = gdtName.indexOf(".gdt");
		gdtName = gdtName.substring(0, ix); // strip-off file extension
		assertEquals(gdtName, sourceArchive.getName());
	}

	@Test
	public void spotCheckWindowsVS12_32() throws IOException {
		ResourceFile gdtFile = Application.getModuleDataFile(WIN_VS12_32_GDT_PATH);
		FileDataTypeManager dtm = FileDataTypeManager.openFileArchive(gdtFile, false);
		try {
			DataType dt = dtm.getDataType("/winsock.h/fd_set");
			assertNotNull(dt);
			assertEquals("2592696207400888580", dt.getUniversalID().toString());
			verifyArchive(dt, WIN_VS12_32_GDT_PATH);
		}
		finally {
			dtm.close();
		}
	}


	@Test
	public void spotCheckWindowsVS12_64() throws IOException {
		ResourceFile gdtFile = Application.getModuleDataFile(WIN_VS12_64_GDT_PATH);
		FileDataTypeManager dtm = FileDataTypeManager.openFileArchive(gdtFile, false);
		try {
			DataType dt = dtm.getDataType("/winsock.h/fd_set");
			assertNotNull(dt);
			assertEquals("3193696894570554681", dt.getUniversalID().toString());
			verifyArchive(dt, WIN_VS12_64_GDT_PATH);
		}
		finally {
			dtm.close();
		}
	}

	@Test
	public void spotCheckGenericCLib32() throws IOException {
		ResourceFile gdtFile = Application.getModuleDataFile(GENERIC_CLIB_32_GDT_PATH);
		FileDataTypeManager dtm = FileDataTypeManager.openFileArchive(gdtFile, false);
		try {
			DataType dt = dtm.getDataType("/select.h/fd_set");
			assertNotNull(dt);
			assertEquals("2592696207400888580", dt.getUniversalID().toString());
			verifyArchive(dt, GENERIC_CLIB_32_GDT_PATH);
		}
		finally {
			dtm.close();
		}
	}

	@Test
	public void spotCheckGenericCLib64() throws IOException {
		ResourceFile gdtFile = Application.getModuleDataFile(GENERIC_CLIB_64_GDT_PATH);
		FileDataTypeManager dtm = FileDataTypeManager.openFileArchive(gdtFile, false);
		try {
			DataType dt = dtm.getDataType("/select.h/fd_set");
			assertNotNull(dt);
			assertEquals("3193700096632251689", dt.getUniversalID().toString());
			verifyArchive(dt, GENERIC_CLIB_64_GDT_PATH);
		}
		finally {
			dtm.close();
		}
	}

	@Test
	public void spotCheckMacOS10_9() throws IOException {
		ResourceFile gdtFile = Application.getModuleDataFile(MAC_OS_10_9_GDT_PATH);
		FileDataTypeManager dtm = FileDataTypeManager.openFileArchive(gdtFile, false);
		try {
			DataType dt = dtm.getDataType("/_fd_def.h/fd_set");
			assertNotNull(dt);
			assertEquals("3015963966244190568", dt.getUniversalID().toString());
			verifyArchive(dt, MAC_OS_10_9_GDT_PATH);
		}
		finally {
			dtm.close();
		}
	}

}
