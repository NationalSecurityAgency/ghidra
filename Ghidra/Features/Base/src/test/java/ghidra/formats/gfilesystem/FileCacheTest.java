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
package ghidra.formats.gfilesystem;

import java.io.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.util.DateUtils;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class FileCacheTest extends AbstractGenericTest {

	private FileCache cache;
	private File cacheDir;
	private TaskMonitor monitor = TaskMonitor.DUMMY;

	@Before
	public void setup() throws IOException {
		cacheDir = createTempDirectory("FileCacheTest");
	}

	@After
	public void tearDown() {
		// keep the cleaner thread from cross-contaminating tests
		waitForCleanup();
	}

	public InputStream toIS(String s) {
		return new ByteArrayInputStream(s.getBytes());
	}

	@Test
	public void testPurge() throws IOException, CancelledException {
		cache = new FileCache(cacheDir);

		FileCacheEntry cfi = cache.addStream(toIS("This is a test1"), monitor);
		Assert.assertTrue(cfi.file.exists());

		File f1 = new File(cacheDir, "file1");
		FileUtilities.writeStringToFile(f1, "test");
		File subdir = new File(cacheDir, "subdir");
		subdir.mkdirs();
		File f2 = new File(subdir, "file2");
		FileUtilities.writeStringToFile(f2, "test2");

		cache.purge();
		Assert.assertFalse(cfi.file.exists());
		Assert.assertTrue(f1.exists());
		Assert.assertTrue(f2.exists());
	}

	@Test
	public void testAgeOff() throws IOException, CancelledException {
		cache = new FileCache(cacheDir);
		waitForCleanup(); // don't let the cache delete the file we are about to create

		FileCacheEntry cfi = cache.addStream(toIS("This is a test1"), monitor);
		Assert.assertTrue(cfi.file.exists());

		cfi.file.setLastModified(System.currentTimeMillis() - (DateUtils.MS_PER_DAY * 5));

		// hack, delete lastmaint file to force a maint event during next cache startup
		File lastMaintFile = new File(cacheDir, ".lastmaint");
		lastMaintFile.delete();

		cache = new FileCache(cacheDir);

		// the file added before should have been purged by the startup of cache2
		waitForCondition(() -> cfi.file.exists());
	}

	@Test
	public void testAddFile() throws IOException, CancelledException {
		cache = new FileCache(cacheDir);

		File tmpFile = createTempFile("filecacheaddfile");
		FileUtilities.writeStringToFile(tmpFile, "This is a test1");

		FileCacheEntry fce = cache.addFile(tmpFile, monitor);
		Assert.assertTrue(fce.file.exists());
		Assert.assertEquals("10428da10f5aa2793cb73c0b680e1621", fce.md5);
		Assert.assertEquals(1, cache.getFileAddCount());
	}

	@Test
	public void testAddStream() throws IOException, CancelledException {
		cache = new FileCache(cacheDir);

		FileCacheEntry fce = cache.addStream(toIS("This is a test1"), monitor);
		Assert.assertTrue(fce.file.exists());
		Assert.assertEquals("10428da10f5aa2793cb73c0b680e1621", fce.md5);
		Assert.assertEquals(1, cache.getFileAddCount());
	}

	@Test
	public void testAddStreamPush() throws IOException, CancelledException {
		cache = new FileCache(cacheDir);

		FileCacheEntry fce = cache.pushStream((os) -> {
			FileUtilities.copyStreamToStream(toIS("This is a test1"), os, monitor);
		}, monitor);
		Assert.assertTrue(fce.file.exists());
		Assert.assertEquals("10428da10f5aa2793cb73c0b680e1621", fce.md5);
		Assert.assertEquals(1, cache.getFileAddCount());
	}

	private void waitForCleanup() {
		waitForCondition(() -> !cache.isCleaning());
	}

}
