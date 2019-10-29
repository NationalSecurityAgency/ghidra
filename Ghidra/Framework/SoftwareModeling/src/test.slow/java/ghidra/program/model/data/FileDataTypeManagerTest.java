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
package ghidra.program.model.data;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import org.junit.*;

import generic.test.AbstractGenericTest;

public class FileDataTypeManagerTest extends AbstractGenericTest {

	private File testArchiveFile;

	@Before
	public void setUp() throws Exception {
		testArchiveFile =
			File.createTempFile("TestArchive", ".gdt", new File(getTestDirectoryPath()));
		testArchiveFile.delete();
	}

	@After
	public void tearDown() throws Exception {
		testArchiveFile.delete();
	}

	@Test
	public void testCreateAndOpenArchive() {

		FileDataTypeManager dtMgr = null;

		try {
			dtMgr = FileDataTypeManager.createFileArchive(testArchiveFile);
			assertTrue(dtMgr.isUpdatable());
			DataType dt1, dt2;
			int txId = dtMgr.startTransaction("Add Types");
			try {
				dt1 =
					dtMgr.addDataType(new TypedefDataType("T1", ByteDataType.dataType), null).clone(
						null);
				dt2 =
					dtMgr.addDataType(new TypedefDataType("T2", ByteDataType.dataType), null).clone(
						null);
			}
			finally {
				dtMgr.endTransaction(txId, true);
			}
			assertTrue(dtMgr.isChanged());
			dtMgr.save();
			dtMgr.close();
			dtMgr = null;

			dtMgr = FileDataTypeManager.openFileArchive(testArchiveFile, false);
			assertFalse(dtMgr.isUpdatable());

			ArrayList<DataType> list = new ArrayList<>();
			dtMgr.getAllDataTypes(list);

			int size = list.size();
			if (size != 3) {

				StringBuilder buffy = new StringBuilder();
				for (DataType dt : list) {
					buffy.append(dt.getName()).append(" - ").append(dt.getDescription()).append(
						"\n");
				}

				Assert.fail(
					"Did not get exptected data types of byte, Typdef and Typedef.  Instead found:\n" +
						buffy.toString());
			}

			assertTrue(dt1.isEquivalent(dtMgr.getDataType(CategoryPath.ROOT, "T1")));
			assertTrue(dt2.isEquivalent(dtMgr.getDataType(CategoryPath.ROOT, "T2")));

			dtMgr.close();
			dtMgr = null;
		}
		catch (IOException e) {
			Assert.fail("Unexpected Exception");
		}
		finally {
			if (dtMgr != null) {
				dtMgr.close();
			}
		}
	}

	@Test
	public void testModifyArchive() {

		testCreateAndOpenArchive(); // establish archive

		for (int i = 0; i < 10; i++) {

			FileDataTypeManager dtMgr = null;
			try {
				dtMgr = FileDataTypeManager.openFileArchive(testArchiveFile, true);
				assertTrue("Archive not updateable, i=" + i, dtMgr.isUpdatable());

				int txId = dtMgr.startTransaction("Add Type");
				try {
					dtMgr.addDataType(new TypedefDataType("X" + i, ByteDataType.dataType), null);

				}
				finally {
					dtMgr.endTransaction(txId, true);
				}

				dtMgr.save();
				dtMgr.close();
				dtMgr = null;
			}
			catch (IOException e) {
				Assert.fail("Unexpected Exception");
			}
			finally {
				if (dtMgr != null) {
					dtMgr.close();
				}
			}

		}

		FileDataTypeManager dtMgr = null;

		try {
			dtMgr = FileDataTypeManager.openFileArchive(testArchiveFile, false);
			assertFalse(dtMgr.isUpdatable());

			ArrayList<DataType> list = new ArrayList<>();
			dtMgr.getAllDataTypes(list);
			assertEquals(13, list.size());

			dtMgr.close();
			dtMgr = null;
		}
		catch (IOException e) {
			Assert.fail("Unexpected Exception");
		}
		finally {
			if (dtMgr != null) {
				dtMgr.close();
			}
		}

	}

}
