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
package ghidra.program.database.sourcemap;

import static org.junit.Assert.*;

import java.util.HexFormat;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.python.google.common.primitives.Longs;

import generic.test.AbstractGenericTest;
import ghidra.framework.store.LockException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.sourcemap.*;
import ghidra.test.ToyProgramBuilder;

public class UserDataPathTransformerTest extends AbstractGenericTest {

	private Program program;
	private ToyProgramBuilder builder;
	private SourceFileManager sourceManager;
	private SourceFile linuxRoot;
	private SourceFile windowsRoot;
	private SourceFile linux1;
	private SourceFile linux2;
	private SourceFile linux3;
	private SourceFile windows1;
	private SourceFile windows2;
	private SourceFile windows3;
	private SourcePathTransformer pathTransformer;

	@Before
	public void setUp() throws Exception {
		builder = new ToyProgramBuilder("testprogram", true, false, this);
		program = builder.getProgram();
		sourceManager = program.getSourceFileManager();
		int txID = program.startTransaction("create source path transformer test program");
		try {
			linuxRoot = new SourceFile("/file1.c");
			sourceManager.addSourceFile(linuxRoot);

			windowsRoot = new SourceFile("/c:/file2.c");
			sourceManager.addSourceFile(windowsRoot);

			linux1 = new SourceFile("/src/dir1/file3.c");
			sourceManager.addSourceFile(linux1);

			linux2 = new SourceFile("/src/dir1/dir2/file4.c");
			sourceManager.addSourceFile(linux2);

			linux3 = new SourceFile("/src/dir1/dir3/file5.c");
			sourceManager.addSourceFile(linux3);

			windows1 = new SourceFile("/c:/src/dir1/file6.c");
			sourceManager.addSourceFile(windows1);

			windows2 = new SourceFile("/c:/src/dir1/dir2/file7.c");
			sourceManager.addSourceFile(windows2);

			windows3 = new SourceFile("/c:/src/dir1/dir3/file8.c");
			sourceManager.addSourceFile(windows3);
		}
		finally {
			program.endTransaction(txID, true);
		}
		pathTransformer = UserDataPathTransformer.getPathTransformer(program);

	}

	@Test(expected = NullPointerException.class)
	public void testNullFileTransform() throws IllegalArgumentException {
		pathTransformer.addFileTransform(null, "/src/test.c");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTransformFileToDirectory() throws IllegalArgumentException {
		pathTransformer.addFileTransform(linux1, "/src/dir/");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTransformFileToRelativePath() throws IllegalArgumentException {
		pathTransformer.addFileTransform(linux1, "src/dir/file.c");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTransformFileToNull() throws IllegalArgumentException {
		pathTransformer.addFileTransform(linux1, null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTransformDirectoryNullSource() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform(null, "/src/");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTransformDirectoryNullDest() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform("/src/test", null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTransformDirectoryToFile() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform("/src/", linux1.getPath());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testApplyDirectoryTransformToFile() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform(linux1.getPath(), "/src/test");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTransformDirectoryInvalidSource1() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform("src/test/", "/source/");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTransformDirectoryInvalidSource2() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform("/src/test", "/source/");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTransformDirectoryInvalidDest1() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform("/source/", "/src/test");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTransformDirectoryInvalidDest2() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform("/source/", "src/test/");
	}

	@Test
	public void testNoDefault() {
		assertNull(pathTransformer.getTransformedPath(linuxRoot, false));
		assertNull(pathTransformer.getTransformedPath(linux1, false));
		assertNull(pathTransformer.getTransformedPath(windowsRoot, false));
		assertNull(pathTransformer.getTransformedPath(windows1, false));
	}

	@Test
	public void testTransformFile() throws IllegalArgumentException {
		pathTransformer.addFileTransform(linux1, "/src/test/newfile.c");
		assertEquals("/src/test/newfile.c", pathTransformer.getTransformedPath(linux1, true));
		assertEquals(linux2.getPath(), pathTransformer.getTransformedPath(linux2, true));
		assertEquals(windowsRoot.getPath(), pathTransformer.getTransformedPath(windowsRoot, true));
	}

	@Test
	public void testTransformLinuxToWindows() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform("/src/dir1/", "/c:/source/");
		assertEquals(linuxRoot.getPath(), pathTransformer.getTransformedPath(linuxRoot, true));
		assertEquals("/c:/source/file3.c", pathTransformer.getTransformedPath(linux1, true));
		assertEquals("/c:/source/dir2/file4.c", pathTransformer.getTransformedPath(linux2, true));
		assertEquals("/c:/source/dir3/file5.c", pathTransformer.getTransformedPath(linux3, true));
	}

	@Test
	public void testTransformWindowsToLinux() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform("/c:/src/dir1/", "/source/");
		assertEquals(windowsRoot.getPath(), pathTransformer.getTransformedPath(windowsRoot, true));
		assertEquals("/source/file6.c", pathTransformer.getTransformedPath(windows1, true));
		assertEquals("/source/dir2/file7.c", pathTransformer.getTransformedPath(windows2, true));
		assertEquals("/source/dir3/file8.c", pathTransformer.getTransformedPath(windows3, true));
	}

	@Test
	public void testAddingMoreSpecificDirectoryTransform() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform("/src/", "/c:/source/");
		assertEquals("/c:/source/dir1/file3.c", pathTransformer.getTransformedPath(linux1, true));
		assertEquals("/c:/source/dir1/dir2/file4.c",
			pathTransformer.getTransformedPath(linux2, true));
		pathTransformer.addDirectoryTransform("/src/dir1/dir2/", "/d:/test/");
		assertEquals("/c:/source/dir1/file3.c", pathTransformer.getTransformedPath(linux1, true));
		assertEquals("/d:/test/file4.c", pathTransformer.getTransformedPath(linux2, true));
		pathTransformer.removeDirectoryTransform("/src/");
		assertEquals(linux1.getPath(), pathTransformer.getTransformedPath(linux1, true));
		assertEquals("/d:/test/file4.c", pathTransformer.getTransformedPath(linux2, true));
		pathTransformer.removeDirectoryTransform("/src/dir1/dir2/");
		assertEquals(linux1.getPath(), pathTransformer.getTransformedPath(linux1, true));
		assertEquals(linux2.getPath(), pathTransformer.getTransformedPath(linux2, true));
	}

	@Test
	public void testAddingDirectoryThenFileTransform() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform("/src/", "/c:/source/");
		assertEquals("/c:/source/dir1/file3.c", pathTransformer.getTransformedPath(linux1, true));
		pathTransformer.addFileTransform(linux1, "/e:/testDirectory/testFile.c");
		assertEquals("/e:/testDirectory/testFile.c",
			pathTransformer.getTransformedPath(linux1, true));
		pathTransformer.removeFileTransform(linux1);
		assertEquals("/c:/source/dir1/file3.c", pathTransformer.getTransformedPath(linux1, true));
		pathTransformer.removeDirectoryTransform("/src/");
		assertEquals(linux1.getPath(), pathTransformer.getTransformedPath(linux1, true));
	}

	@Test
	public void testUniqueness() {
		SourcePathTransformer transformer2 = UserDataPathTransformer.getPathTransformer(program);
		assertTrue(transformer2 == pathTransformer);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNormalizedFile() throws IllegalArgumentException {
		pathTransformer.addFileTransform(linux1, "/src/dir1/../dir2/file.c");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNormalizedSourceDirectory() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform("/src/dir1/../dir2/", "/test/");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNormalizedDestDirectory() throws IllegalArgumentException {
		pathTransformer.addDirectoryTransform("/test/", "src/dir1/../dir2/");
	}

	@Test
	public void testGetTransformRecords() throws IllegalArgumentException {
		assertEquals(0, pathTransformer.getTransformRecords().size());
		pathTransformer.addFileTransform(linux1, "/test/file10.c");
		List<SourcePathTransformRecord> transformRecords = pathTransformer.getTransformRecords();
		assertEquals(1, transformRecords.size());
		assertEquals(linux1, transformRecords.get(0).sourceFile());
		assertEquals("/test/file10.c", transformRecords.get(0).target());

		pathTransformer.addFileTransform(linux1, "/test/file20.c");
		transformRecords = pathTransformer.getTransformRecords();
		assertEquals(1, transformRecords.size());
		assertEquals(linux1, transformRecords.get(0).sourceFile());
		assertEquals("/test/file20.c", transformRecords.get(0).target());

		pathTransformer.addFileTransform(linux2, "/test/file30.c");
		transformRecords = pathTransformer.getTransformRecords();
		assertEquals(2, transformRecords.size());
		SourcePathTransformRecord rec1 =
			new SourcePathTransformRecord("NONE##" + linux1.getPath(), linux1, "/test/file20.c");
		SourcePathTransformRecord rec2 =
			new SourcePathTransformRecord("NONE##" + linux2.getPath(), linux2, "/test/file30.c");
		assertTrue(transformRecords.contains(rec1));
		assertTrue(transformRecords.contains(rec2));

		pathTransformer.addDirectoryTransform("/a/b/c/", "/d/e/f/");
		transformRecords = pathTransformer.getTransformRecords();
		assertEquals(3, transformRecords.size());
		SourcePathTransformRecord rec3 = new SourcePathTransformRecord("/a/b/c/", null, "/d/e/f/");
		assertTrue(transformRecords.contains(rec1));
		assertTrue(transformRecords.contains(rec2));
		assertTrue(transformRecords.contains(rec3));

		pathTransformer.addDirectoryTransform("/a/b/c/", "/g/h/i/");
		transformRecords = pathTransformer.getTransformRecords();
		assertEquals(3, transformRecords.size());
		SourcePathTransformRecord rec4 = new SourcePathTransformRecord("/a/b/c/", null, "/g/h/i/");
		assertTrue(transformRecords.contains(rec1));
		assertTrue(transformRecords.contains(rec2));
		assertTrue(transformRecords.contains(rec4));

	}

	@Test
	public void testFileTransformsAndIdentifiers() throws LockException {
		SourceFile source1 = new SourceFile("/src/file.c");
		SourceFile source2 =
			new SourceFile("/src/file.c", SourceFileIdType.TIMESTAMP_64, Longs.toByteArray(0));
		SourceFile source3 = new SourceFile("/src/file.c", SourceFileIdType.MD5,
			HexFormat.of().parseHex("0123456789abcdef0123456789abcdef"));

		int txId = program.startTransaction("adding source files");
		try {
			sourceManager.addSourceFile(source1);
			sourceManager.addSourceFile(source2);
			sourceManager.addSourceFile(source3);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals("/src/file.c", pathTransformer.getTransformedPath(source1, true));
		assertEquals("/src/file.c", pathTransformer.getTransformedPath(source2, true));
		assertEquals("/src/file.c", pathTransformer.getTransformedPath(source3, true));

		pathTransformer.addFileTransform(source1, "/transformedFile/file.c");
		assertEquals("/transformedFile/file.c", pathTransformer.getTransformedPath(source1, true));
		assertEquals("/src/file.c", pathTransformer.getTransformedPath(source2, true));
		assertEquals("/src/file.c", pathTransformer.getTransformedPath(source3, true));

		pathTransformer.addFileTransform(source2, "/transformedFile/file2.c");
		assertEquals("/transformedFile/file.c", pathTransformer.getTransformedPath(source1, true));
		assertEquals("/transformedFile/file2.c", pathTransformer.getTransformedPath(source2, true));
		assertEquals("/src/file.c", pathTransformer.getTransformedPath(source3, true));

		pathTransformer.addDirectoryTransform("/src/", "/SOURCE/");
		assertEquals("/transformedFile/file.c", pathTransformer.getTransformedPath(source1, true));
		assertEquals("/transformedFile/file2.c", pathTransformer.getTransformedPath(source2, true));
		assertEquals("/SOURCE/file.c", pathTransformer.getTransformedPath(source3, true));

		pathTransformer.removeFileTransform(source2);
		assertEquals("/transformedFile/file.c", pathTransformer.getTransformedPath(source1, true));
		assertEquals("/SOURCE/file.c", pathTransformer.getTransformedPath(source2, true));
		assertEquals("/SOURCE/file.c", pathTransformer.getTransformedPath(source3, true));
	}

	@Test
	public void testTransformerForNullProgram() {
		assertNull(UserDataPathTransformer.getPathTransformer(null));
	}
}
