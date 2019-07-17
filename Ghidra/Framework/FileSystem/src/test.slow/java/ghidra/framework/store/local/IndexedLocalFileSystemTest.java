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
package ghidra.framework.store.local;

import static org.junit.Assert.*;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import ghidra.framework.store.DataFileItem;

public class IndexedLocalFileSystemTest extends AbstractLocalFileSystemTest {

	public IndexedLocalFileSystemTest() {
		super(true);
	}

	@Test
	public void testIndexRecovery() throws Exception {

		testFilePaths();

		List<String> names = new ArrayList<>();
		for (String itemName : fs.getItemNames("/a/x/bbb")) {
			names.add(itemName);
		}

		// re-instantiate file-system (index will not have been rewritten)
		// journal will be replayed to build memory-based index

//		IndexedLocalFileSystem.IndexJournal indexJournal =
//			(IndexedLocalFileSystem.IndexJournal) getInstanceField("indexJournal", fs);
		//indexJournal.close();

		fs = LocalFileSystem.getLocalFileSystem(projectDir.getAbsolutePath(), false, false, false,
			true);

		for (String itemName : names) {
			DataFileItem item = (DataFileItem) fs.getItem("/a/x/bbb", itemName);
			assertNotNull(item);
			assertEquals(itemName, item.getName());
			assertEquals("/a/x/bbb", item.getParentPath());
			assertEquals("/a/x/bbb/" + itemName, item.getPathName());
			InputStream is = item.getInputStream();
			assertNotNull(is);
			is.close();
		}

	}

	@Test
	public void testIndexRebuild() throws Exception {

		testFilePaths();

		List<String> names = new ArrayList<>();
		for (String itemName : fs.getItemNames("/a/x/bbb")) {
			names.add(itemName);
		}

		fs.dispose();

		// verify index exists
		File indexFile = new File(projectDir, IndexedLocalFileSystem.INDEX_FILE);
		assertTrue(indexFile.exists());
		File journalFile = new File(projectDir, IndexedLocalFileSystem.JOURNAL_FILE);
		assertTrue(!journalFile.exists());

		// verify that revised property files can facilitate index rebuild

		assertTrue(indexFile.delete());

		// can we still identify it as a Indexed FileSystem ?
		assertTrue(IndexedLocalFileSystem.hasIndexedStructure(projectDir.getAbsolutePath()));

		// reopen filesystem and verify contents after auto-rebuild
		fs = LocalFileSystem.getLocalFileSystem(projectDir.getAbsolutePath(), false, false, false,
			true);

		for (String itemName : names) {
			DataFileItem item = (DataFileItem) fs.getItem("/a/x/bbb", itemName);
			assertNotNull("/a/x/bbb/" + itemName + " not found", item);
			assertEquals(itemName, item.getName());
			assertEquals("/a/x/bbb", item.getParentPath());
			assertEquals("/a/x/bbb/" + itemName, item.getPathName());
			InputStream is = item.getInputStream();
			assertNotNull(is);
			is.close();
		}
	}

}
