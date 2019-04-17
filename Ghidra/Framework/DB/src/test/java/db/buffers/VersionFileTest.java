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
package db.buffers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import utilities.util.FileUtilities;

public class VersionFileTest extends AbstractGenericTest {

	private static int BUFFER_SIZE = LocalBufferFile.getRecommendedBufferSize(500);

	private File testDir = new File(AbstractGenericTest.getTestDirectoryPath(), "test");

	private Random random = new Random();

	@Before
	public void setUp() throws Exception {

		testDir = createTempDirectory(getClass().getSimpleName());
	}

	@After
	public void tearDown() throws Exception {
		FileUtilities.deleteDir(testDir);
	}

	@Test
	public void testVersionFile() throws Exception {

		// Make sure we stress the VersionFile storage
		int origFreeBufCount = BUFFER_SIZE / 2;
		int origBufCount = origFreeBufCount * 2;

		byte[][] testData = new byte[origBufCount][BUFFER_SIZE];
		int[] testIndexes = new int[origBufCount];
		for (int i = 0; i < origBufCount; i++) {
			random.nextBytes(testData[i]);
			testIndexes[i] = -1;
		}

		// Create original buffer file
		IndexProvider indexProvider = new IndexProvider();
		File origFile = new File(testDir, "test.1.bf");
		origFile.delete();
		LocalBufferFile origBf = new LocalBufferFile(origFile, BUFFER_SIZE);

		// Add data buffers to original file
		DataBuffer buf = new DataBuffer();
		for (int i = 0; i < origBufCount; i++) {
			testIndexes[i] = indexProvider.allocateIndex();
			assertEquals(i, testIndexes[i]);
			buf.data = testData[i];
			buf.setId(i);
			buf.setEmpty(false);
			origBf.put(buf, testIndexes[i]);
		}

		// Remove every other buffer (build-up free list)
		for (int i = 1; i < origBufCount; i += 2) {
			indexProvider.freeIndex(testIndexes[i]);
		}

		// Set a few parms
		origBf.setParameter("PARM1", 111);
		origBf.setParameter("PARM2", 222);

		// Set free list
		int[] origFreeIndexes = origBf.getFreeIndexes();
		origBf.setFreeIndexes(origFreeIndexes);

		// Create target buffer file (only need for target ID)
		File targetFile = new File(testDir, "test.2.bf");
		targetFile.delete();
		LocalBufferFile targetBf = new LocalBufferFile(targetFile, BUFFER_SIZE);

		// Create version file
		File verFile = new File(testDir, "test.1.vf");
		verFile.delete();
		VersionFile vf = new VersionFile(origBf, targetBf, verFile);
		assertEquals(targetBf.getFileId(), vf.getTargetFileID());
		assertEquals(origBf.getFileId(), vf.getOriginalFileID());

		// Delete buffer files
		origBf.delete();
		targetBf.delete();

		// Add "modified" buffers to version file
		for (int i = 0; i < origBufCount; i += 2) {
			buf.data = testData[i];
			buf.setId(i);
			buf.setEmpty(false);
			vf.putOldBuffer(buf, i);
		}

		// Save file
		vf.close();

		// Reopen version file read-only
		vf = new VersionFile(verFile);
		assertEquals(origBufCount, vf.getOriginalBufferCount());
		assertEquals(targetBf.getFileId(), vf.getTargetFileID());
		assertEquals(origBf.getFileId(), vf.getOriginalFileID());

		int[] freeIndexes = vf.getFreeIndexList();
		int[] bufferIndexes = vf.getOldBufferIndexes();
		vf.close();

		// Verify free list
		assertEquals(origFreeIndexes.length, freeIndexes.length);
		Arrays.sort(origFreeIndexes);
		Arrays.sort(freeIndexes);
		for (int i = 0; i < origFreeIndexes.length; i++) {
			assertEquals(origFreeIndexes[i], freeIndexes[i]);
		}

		// Reopen
		vf.open();

		// Verify buffer list and associated buffers
		assertEquals(origBufCount / 2, bufferIndexes.length);
		Arrays.sort(bufferIndexes);
		int ix = 0;
		for (int i = 0; i < origBufCount; i += 2) {
			assertEquals(testIndexes[i], bufferIndexes[ix]);
			buf = vf.getOldBuffer(buf, bufferIndexes[ix]);
			assertTrue(Arrays.equals(testData[i], buf.data));
			++ix;
		}

		String[] names = vf.getOldParameterNames();
		assertEquals(2, names.length);
		Arrays.sort(names);
		assertEquals("PARM1", names[0]);
		assertEquals("PARM2", names[1]);
		assertEquals(111, vf.getOldParameter("PARM1"));
		assertEquals(222, vf.getOldParameter("PARM2"));

		try {
			vf.getOldParameter("PARM3");
			Assert.fail();
		}
		catch (NoSuchElementException e) {
			// expected
		}

		vf.close();

	}

}
