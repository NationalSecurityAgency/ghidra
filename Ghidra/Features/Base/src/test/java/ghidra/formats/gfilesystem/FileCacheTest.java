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

import static org.junit.Assert.*;

import java.io.*;
import java.util.Arrays;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.ObfuscatedInputStream;
import ghidra.formats.gfilesystem.FileCache.FileCacheEntry;
import ghidra.formats.gfilesystem.FileCache.FileCacheEntryBuilder;
import ghidra.util.DateUtils;
import utilities.util.FileUtilities;

public class FileCacheTest extends AbstractGenericTest {

	private FileCache cache;
	private File cacheDir;

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

	FileCacheEntry createCacheFile(String payload) throws IOException {
		// lie about the sizeHint to force the cache entry to be saved into a file instead of
		// memory only
		FileCacheEntryBuilder fceBuilder = cache.createCacheEntryBuilder(Integer.MAX_VALUE);
		fceBuilder.write(payload.getBytes());
		FileCacheEntry fce = fceBuilder.finish();
		return fce;
	}

	@Test
	public void testPurge() throws IOException {
		cache = new FileCache(cacheDir);

		FileCacheEntry fce = createCacheFile("blah");

		Assert.assertTrue(fce.file.exists());

		File f1 = new File(cacheDir, "file1");
		FileUtilities.writeStringToFile(f1, "test");
		File subdir = new File(cacheDir, "subdir");
		subdir.mkdirs();
		File f2 = new File(subdir, "file2");
		FileUtilities.writeStringToFile(f2, "test2");

		cache.purge();
		Assert.assertFalse(fce.file.exists());
		Assert.assertTrue(f1.exists());
		Assert.assertTrue(f2.exists());
	}

	@Test
	public void testAgeOff() throws IOException {
		// hack, delete lastmaint file to force a maint event during next cache startup
		File lastMaintFile = new File(cacheDir, ".lastmaint");
		lastMaintFile.delete();

		cache = new FileCache(cacheDir);
		waitForCleanup(); // don't let the cache delete the file we are about to create

		FileCacheEntry fce = createCacheFile("test");
		Assert.assertTrue(fce.file.exists());

		// backdate the file so it should appear to be old and age-off-able
		fce.file.setLastModified(System.currentTimeMillis() - (DateUtils.MS_PER_DAY * 5));

		// hack, delete lastmaint file to force a maint event during next cache startup
		lastMaintFile.delete();

		cache = new FileCache(cacheDir);

		// the file added before should have been deleted by the startup of cache2
		waitForCleanup();
		assertFalse(fce.file.exists());
	}

	@Test
	public void testCacheFileBadFilename() throws IOException {
		// test to ensure bad filenames in the cache dir don't cause problem

		// hack, delete lastmaint file to force a maint event during next cache startup
		File lastMaintFile = new File(cacheDir, ".lastmaint");
		lastMaintFile.delete();

		cache = new FileCache(cacheDir);
		waitForCleanup(); // don't let the cache delete the file we are about to create

		FileCacheEntry fce = createCacheFile("test");
		Assert.assertTrue(fce.file.exists());

		// backdate the file so it should appear to be old and age-off-able
		fce.file.setLastModified(System.currentTimeMillis() - (DateUtils.MS_PER_DAY * 5));

		// do same for file with bad filename
		File badFile = new File(fce.file.getParentFile(), "bad_filename");
		FileUtilities.writeStringToFile(badFile, "bad file contents");
		badFile.setLastModified(System.currentTimeMillis() - (DateUtils.MS_PER_DAY * 5));

		// hack, delete lastmaint file to force a maint event during next cache startup
		lastMaintFile.delete();

		cache = new FileCache(cacheDir);

		// the file added before should have been deleted by the startup of cache2
		waitForCleanup();
		assertFalse(fce.file.exists());
		assertTrue(badFile.exists());
	}

	@Test
	public void testAddFile() throws IOException {
		cache = new FileCache(cacheDir);

		FileCacheEntry fce = createCacheFile("This is a test1");
		assertTrue(fce.file.exists());
		assertEquals("10428da10f5aa2793cb73c0b680e1621", fce.md5);
	}

	@Test
	public void testFileObfuscated() throws IOException {
		cache = new FileCache(cacheDir);

		FileCacheEntry fce = createCacheFile("This is a test1");
		assertTrue(fce.file.exists());
		assertEquals("10428da10f5aa2793cb73c0b680e1621", fce.md5);

		byte[] fileBytes = FileUtilities.getBytesFromFile(fce.file);
		assertFalse(Arrays.equals("This is a test1".getBytes(), fileBytes));

		try (ObfuscatedInputStream ois = new ObfuscatedInputStream(new FileInputStream(fce.file))) {
			byte[] buffer = new byte[100];
			int bytesRead = ois.read(buffer);
			assertEquals(15, bytesRead);
			assertTrue(Arrays.equals("This is a test1".getBytes(), 0, 15, buffer, 0, 15));
		}
	}

	@Test
	public void testAddSmallFile() throws IOException {
		cache = new FileCache(cacheDir);

		FileCacheEntryBuilder fceBuilder = cache.createCacheEntryBuilder(-1);
		fceBuilder.write("This is a test1".getBytes());
		FileCacheEntry fce = fceBuilder.finish();
		assertNull(fce.file);
		assertEquals("10428da10f5aa2793cb73c0b680e1621", fce.md5);
		assertEquals(15, fce.bytes.length);
	}

	@Test
	public void testBoundaryCondition() throws IOException {
		// test that writing 1 byte less than size cutoff doesn't trigger switch to disk file
		cache = new FileCache(cacheDir);

		FileCacheEntryBuilder fceBuilder = cache.createCacheEntryBuilder(-1);
		byte[] bytes = new byte[FileCache.MAX_INMEM_FILESIZE - 1];
		fceBuilder.write(bytes);
		FileCacheEntry fce = fceBuilder.finish();
		assertNull(fce.file);
		assertEquals(FileCache.MAX_INMEM_FILESIZE - 1, fce.bytes.length);
	}

	@Test
	public void testBoundaryCondition_Grow() throws IOException {
		// test that writing more than size cutoff does trigger switch to disk file
		cache = new FileCache(cacheDir);

		FileCacheEntryBuilder fceBuilder = cache.createCacheEntryBuilder(-1);
		byte[] bytes = new byte[FileCache.MAX_INMEM_FILESIZE - 1];
		fceBuilder.write(bytes);
		fceBuilder.write(0);
		fceBuilder.write(0);
		FileCacheEntry fce = fceBuilder.finish();
		assertNotNull(fce.file);
		assertEquals("4eda5bcf5ef0cd4066425006dba9ffaa", fce.md5);
	}

	@Test
	public void testLargeFile() throws IOException {
		cache = new FileCache(cacheDir);

		FileCacheEntryBuilder fceBuilder =
			cache.createCacheEntryBuilder(FileCache.MAX_INMEM_FILESIZE + 1);
		byte[] bytes = new byte[FileCache.MAX_INMEM_FILESIZE + 1];
		fceBuilder.write(bytes);
		FileCacheEntry fce = fceBuilder.finish();
		assertNotNull(fce.file);
		assertEquals("4eda5bcf5ef0cd4066425006dba9ffaa", fce.md5);
	}

	private void waitForCleanup() {
		waitForCondition(() -> !cache.isCleaning());
	}

}
