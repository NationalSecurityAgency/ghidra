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
package utilities.util;

import static generic.test.AbstractGTest.assertListEqualsArrayOrdered;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

import java.io.*;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import utilities.util.FileResolutionResult.FileResolutionStatus;

public class FileUtilitiesTest {

	@Test
	public void testPathToParts_ForwardSlash() {

		String[] parts = { "a", "b", "c", "file.txt" };
		String path = StringUtils.join(parts, '/');
		List<String> list = FileUtilities.pathToParts(path);
		assertEquals(parts.length, list.size());
		assertListEqualsArrayOrdered(list, parts);
	}

	@Test
	public void testPathToParts_BackwardSlash() {

		String[] parts = { "a", "b", "c", "file.txt" };
		String path = StringUtils.join(parts, '/');
		List<String> list = FileUtilities.pathToParts(path);
		assertEquals(parts.length, list.size());
		assertListEqualsArrayOrdered(list, parts);
	}

	@Test
	public void testPathIsCaseDependent_SingleDot() {

		String canonical = "/a/b/file.txt";
		String absolute = "/a/b/c/./file.txt";
		FileResolutionResult result = FileUtilities.pathIsCaseDependent(canonical, absolute);
		assertEquals(FileResolutionStatus.OK, result.getStatus());
	}

	@Test
	public void testPathIsCaseDependent_SingleDotDot() {

		String canonical = "/a/b/file.txt";
		String absolute = "/a/b/c/../file.txt";
		FileResolutionResult result = FileUtilities.pathIsCaseDependent(canonical, absolute);
		assertEquals(FileResolutionStatus.OK, result.getStatus());
	}

	@Test
	public void testPathIsCaseDependent_Invalid_UpperEndOfPath_SingleDotDot() {

		String canonical = "/a/b/file.txt";
		String absolute = "/A/b/c/../file.txt";
		FileResolutionResult result = FileUtilities.pathIsCaseDependent(canonical, absolute);
		assertEquals(FileResolutionStatus.NotProperlyCaseDependent, result.getStatus());
	}

	@Test
	public void testPathIsCaseDependent_Invalid_SingleDotDot() {

		String canonical = "/a/b/file.txt";
		String absolute = "/a/b/c/../File.txt";
		FileResolutionResult result = FileUtilities.pathIsCaseDependent(canonical, absolute);
		assertEquals(FileResolutionStatus.NotProperlyCaseDependent, result.getStatus());
	}

	@Test
	public void testExistsAndIsCaseDependent_Valid() throws Exception {

		ResourceFile file = createNestedTempFile("/a/b/c/d/");
		FileResolutionResult result = FileUtilities.existsAndIsCaseDependent(file);
		assertEquals(FileResolutionStatus.OK, result.getStatus());
	}

	@Test
	public void testExistsAndIsCaseDependent_Invalid() throws Exception {

		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.LINUX) {
			// This test only works when the case is ignored
			return;
		}

		ResourceFile file = createNestedTempFile("/a/b/c/d/");
		String path = file.getAbsolutePath();
		String invalidPath = path.replaceAll("a/b/c", "A/b/C");
		ResourceFile badCaseFile = new ResourceFile(invalidPath);
		FileResolutionResult result = FileUtilities.existsAndIsCaseDependent(badCaseFile);
		assertEquals(FileResolutionStatus.NotProperlyCaseDependent, result.getStatus());
	}

	@Test
	public void testRelativizePath() throws IOException {
		File f1 = new File("/a/b");
		File f2 = new File("/a/b/c");
		String relative = FileUtilities.relativizePath(f1, f2);
		assertEquals("c", relative);
	}

	@Test
	public void testRelativizePath_NotRelated() throws IOException {
		File f1 = new File("/a/b");
		File f2 = new File("/c/d");
		String relative = FileUtilities.relativizePath(f1, f2);
		assertNull(relative);
	}

	@Test
	public void testRelativizePath_Same() throws IOException {
		File f1 = new File("/a/b");
		File f2 = new File("/a/b");
		String relative = FileUtilities.relativizePath(f1, f2);
		assertNull(relative);
	}

	@Test
	public void testRelativizePath_ResourceFiles() {
		ResourceFile f1 = new ResourceFile(new File("/a/b"));
		ResourceFile f2 = new ResourceFile(new File("/a/b/c"));
		String relative = FileUtilities.relativizePath(f1, f2);
		assertEquals("c", relative);
	}

	@Test
	public void testRelativizePath_ResourceFiles2() {
		ResourceFile f1 = new ResourceFile(new File("/a/b"));
		ResourceFile f2 = new ResourceFile(new File("/a/b/c/d"));
		String relative = FileUtilities.relativizePath(f1, f2);
		assertEquals("c/d", relative);
	}

	@Test
	public void testRelativizePath_ResourceFiles_NotRelated() {
		ResourceFile f1 = new ResourceFile(new File("/a/b"));
		ResourceFile f2 = new ResourceFile(new File("/c/d"));
		String relative = FileUtilities.relativizePath(f1, f2);
		assertNull(relative);
	}

	@Test
	public void testRelativizePath_ResourceFiles_Same() {
		ResourceFile f1 = new ResourceFile(new File("/a/b"));
		ResourceFile f2 = new ResourceFile(new File("/a/b"));
		String relative = FileUtilities.relativizePath(f1, f2);
		assertNull(relative);
	}

	private ResourceFile createNestedTempFile(String path) throws Exception {

		String tmpdir = AbstractGenericTest.getTestDirectoryPath();
		String parentPath = tmpdir + path;
		File parentDir = new File(parentPath);
		FileUtilities.mkdirs(parentDir);
		File tempFile = File.createTempFile("FileUtilitiesTest", ".txt", parentDir);
		ResourceFile resourceFile = new ResourceFile(tempFile);
		return resourceFile;
	}

	@Test
	public void testIsPathContainedWithin() {
		assertTrue(FileUtilities.isPathContainedWithin(new File("/a/b"), new File("/a/b/c")));
		assertTrue(FileUtilities.isPathContainedWithin(new File("/a/b"), new File("/a/b")));
		assertTrue(FileUtilities.isPathContainedWithin(new File("/a/b"), new File("/a/b/../b/c")));
		assertTrue(FileUtilities.isPathContainedWithin(new File("/a/b/"), new File("/a/b")));

		assertFalse(FileUtilities.isPathContainedWithin(new File("/a/b"), new File("/c")));
		assertFalse(FileUtilities.isPathContainedWithin(new File("/a/b"), new File("/a/b/../c")));
		assertFalse(FileUtilities.isPathContainedWithin(new File("/a/b"), new File("/a/bc")));
	}

	@Test
	public void copyFile_ResourceFile_To_ResourceFile() throws Exception {

		File from = File.createTempFile("from.file", ".txt");
		FileUtilities.writeLinesToFile(from, Arrays.asList("From file contents"));
		from.deleteOnExit();

		File to = File.createTempFile("to.file", ".txt");
		to.deleteOnExit();
		FileUtilities.writeLinesToFile(to, Arrays.asList("To file contents"));

		FileUtilities.copyFile(new ResourceFile(from), new ResourceFile(to), null);

		String text = FileUtils.readFileToString(to, Charset.defaultCharset());
		assertThat(text, equalTo("From file contents\n"));
	}

	@Test(expected = IOException.class)
	public void copyFile_ExceptionFromInputStream() throws Exception {

		ResourceFile from = new ResourceFile(new File("/fake.from.file")) {
			@Override
			public InputStream getInputStream() throws IOException {
				throw new IOException("Test Exception");
			}
		};

		File to = File.createTempFile("to.file", ".txt");
		to.deleteOnExit();

		// should fail
		FileUtilities.copyFile(from, new ResourceFile(to), null);
	}

	@Test(expected = IOException.class)
	public void copyFile_ExceptionFromOutputStream() throws Exception {

		File from = File.createTempFile("from.file", ".txt");
		from.deleteOnExit();

		ResourceFile to = new ResourceFile(new File("/to.from.file")) {

			@Override
			public OutputStream getOutputStream() throws FileNotFoundException {
				throw new FileNotFoundException("Test Exception");
			}
		};

		// should fail
		FileUtilities.copyFile(new ResourceFile(from), to, null);
	}

	public void copyFile_WithMonitor() {
		// too slow due to the nature of how the progress is reported in chunks--we would
		// have to generate too much data, which would take seconds to test that progress
		// is correctly reported
	}
}
