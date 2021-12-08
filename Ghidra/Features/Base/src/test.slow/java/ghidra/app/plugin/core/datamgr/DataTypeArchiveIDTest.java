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
import ghidra.program.model.data.FileDataTypeManager;

public class DataTypeArchiveIDTest extends AbstractGenericTest {

	private static final HashMap<String, String> archiveIdMap = new HashMap<>();
	static {
		archiveIdMap.put("typeinfo/win32/windows_vs12_32.gdt", "2644092282468053077");
		archiveIdMap.put("typeinfo/win32/windows_vs12_64.gdt", "3193696833254024484");
		archiveIdMap.put("typeinfo/generic/generic_clib_64.gdt", "3193699959493190971");
		archiveIdMap.put("typeinfo/generic/generic_clib.gdt", "2644097909188870631");
		archiveIdMap.put("typeinfo/mac_10.9/mac_osx.gdt", "2650667045259492112");
	}

	@Test
	public void testIDMatch() throws IOException {

		HashSet<String> notFound = new HashSet<>(archiveIdMap.keySet());

		for (ResourceFile dtFile : Application.findFilesByExtensionInApplication(".gdt")) {

			String path = dtFile.getAbsolutePath();
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

			FileDataTypeManager dtm = FileDataTypeManager.openFileArchive(dtFile, false);
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

}
