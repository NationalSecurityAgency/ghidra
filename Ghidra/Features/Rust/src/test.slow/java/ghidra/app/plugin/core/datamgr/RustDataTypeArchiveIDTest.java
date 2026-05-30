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
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.junit.Test;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.framework.Application;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.StandAloneDataTypeManager.ArchiveWarning;

public class RustDataTypeArchiveIDTest extends AbstractGenericTest {

	//@formatter:off
	private static final Map<String, String> archiveIdMap = Map.ofEntries(
			Map.entry("typeinfo/rust-common.gdt", "3557867258392862055"));
	//@formatter:on

	private Map<ResourceFile, String> getCurrentGdts() {
		return Application.findFilesByExtensionInMyModule(".gdt")
				.stream()
				.filter(f -> f.getAbsolutePath().replace('\\', '/').contains("/data/typeinfo/"))
				.collect(Collectors.toMap(Function.identity(), f -> getGdtUniversalId(f)));
	}

	private String getGdtUniversalId(ResourceFile gdtFile) {
		FileDataTypeManager dtm = null;
		try {
			dtm = FileDataTypeManager.openFileArchive(gdtFile, false);
			assertEquals(dtm.getWarningMessage(true), ArchiveWarning.NONE, dtm.getWarning());
			return dtm.getUniversalID().toString();
		}
		catch (IOException e) {
			return "failed to read " + gdtFile.getName();
		}
		finally {
			dtm.close();
		}
	}

	private String getGdtRelativePath(ResourceFile gdtFile) {
		String path = gdtFile.getAbsolutePath().replace('\\', '/');
		int ix = path.indexOf("/typeinfo/");
		path = path.substring(ix + 1);
		return path;
	}

	@Test
	public void testArchiveIDMatch() {

		Map<ResourceFile, String> currentGdts = getCurrentGdts();
		Set<String> notFound = new HashSet<>(archiveIdMap.keySet());
		for (ResourceFile gdtFile : currentGdts.keySet()) {
			String currentID = currentGdts.get(gdtFile);

			String gdtRelativePath = getGdtRelativePath(gdtFile);
			String oldID = archiveIdMap.get(gdtRelativePath);
			if (oldID == null) {
				fail("New archive added, test must be updated: %s, ID: %s"
						.formatted(gdtRelativePath, currentID));
			}

			notFound.remove(gdtRelativePath);

			assertEquals("Archive UniversalID mismatch: " + gdtRelativePath, oldID, currentID);
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
