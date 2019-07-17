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

import static generic.test.AbstractGenericTest.assertListEqualsArrayOrdered;
import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.List;

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
}
