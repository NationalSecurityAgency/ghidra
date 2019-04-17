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
package ghidra.feature.fid.db;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class FidFileManagerTest extends AbstractGenericTest {

	private FidFileManager fidFileMgr;
	private int startingSize;

	@Before
	public void setup() {
		fidFileMgr = FidFileManager.getInstance();
		startingSize = fidFileMgr.getFidFiles().size();
	}

	@Test
	public void testSaveRestore() throws IOException {
		File tempFile1 = createTempFile("FID1", ".ser");
		File tempFile2 = createTempFile("FID2 ", ".ser");
		tempFile1.delete();
		tempFile2.delete();
		createFid(tempFile1);
		createFid(tempFile2);

		FidFile fidFile1 = fidFileMgr.addUserFidFile(tempFile1);
		FidFile fidFile2 = fidFileMgr.addUserFidFile(tempFile2);
		fidFile1.setActive(false);

		// for test purposes, construct a new FidFileManager to see if the preferences are set
		FidFileManager newFileManager = (FidFileManager) invokeConstructor(FidFileManager.class,
			new Class<?>[0], new Object[0]);

		List<FidFile> fidFiles = newFileManager.getFidFiles();

		assertEquals(startingSize + 2, fidFiles.size());

		for (FidFile ff : fidFiles) {
			if (ff.getFile().equals(tempFile1)) {
				assertTrue(!ff.isActive());
			}
			if (ff.getFile().equals(tempFile2)) {
				assertTrue(ff.isActive());
			}
		}

		fidFile1.setActive(true);
		fidFile2.setActive(true);

		// for test purposes, construct a new FidFileManager
		newFileManager = (FidFileManager) invokeConstructor(FidFileManager.class, new Class<?>[0],
			new Object[0]);
		fidFiles = newFileManager.getFidFiles();

		for (FidFile ff : fidFiles) {
			if (ff.getFile().equals(tempFile1)) {
				assertTrue(ff.isActive());
			}
			if (ff.getFile().equals(tempFile2)) {
				assertTrue(ff.isActive());
			}
		}

	}

	private void createFid(File databaseFile) throws IOException {
		fidFileMgr.createNewFidDatabase(databaseFile);
	}
}
