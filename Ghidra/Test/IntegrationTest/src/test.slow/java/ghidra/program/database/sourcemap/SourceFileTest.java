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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.python.google.common.primitives.Longs;

import ghidra.framework.store.LockException;
import ghidra.util.SourceFileUtils;

public class SourceFileTest extends AbstractSourceFileTest {

	@Test(expected = IllegalArgumentException.class)
	public void testNonFilePathFailure() {
		new SourceFile("/test/dir/");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRelativePathCreateFailure() {
		new SourceFile("test1/test2.c");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNullPathCreateFailure() {
		new SourceFile((String) null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testEmptyPathCreateFailure() {
		new SourceFile(StringUtils.EMPTY);
	}

	@Test
	public void testPathNormalization() {
		assertEquals("/src/dir1/dir2/file.c",
			new SourceFile("/src/test/../dir1/test/../dir2/file.c").getPath());
	}

	@Test
	public void testGetFilename() {
		assertEquals("file.c", new SourceFile("/src/test/file.c").getFilename());
	}

	@Test
	public void testUtilityMethod() {
		SourceFile linux = SourceFileUtils.getSourceFileFromPathString("/src/test/../file1.c");
		assertEquals("/src/file1.c", linux.getPath());
		assertEquals("file1.c", linux.getFilename());

		SourceFile windows =
			SourceFileUtils.getSourceFileFromPathString("c:\\src\\test\\..\\file1.c");
		assertEquals("/c:/src/file1.c", windows.getPath());
		assertEquals("file1.c", windows.getFilename());

		windows =
			SourceFileUtils.getSourceFileFromPathString("/C:/Users//guest/./temp/../file.exe");
		assertEquals("/C:/Users/guest/file.exe", windows.getPath());
		assertEquals("file.exe", windows.getFilename());
	}

	@Test
	public void basicAddRemoveTest() throws LockException {
		assertEquals(3, sourceManager.getAllSourceFiles().size());
		SourceFile testSource = new SourceFile("/home/user/src/file.c");

		int txId = program.startTransaction("adding source file");
		try {
			assertTrue(sourceManager.addSourceFile(testSource));
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(4, sourceManager.getAllSourceFiles().size());

		txId = program.startTransaction("adding same source file");
		try {
			assertFalse(sourceManager.addSourceFile(testSource));
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(4, sourceManager.getAllSourceFiles().size());

		txId = program.startTransaction("removing source file");
		try {
			assertTrue(sourceManager.removeSourceFile(testSource));
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(3, sourceManager.getAllSourceFiles().size());

		txId = program.startTransaction("removing source file again");
		try {
			assertFalse(sourceManager.removeSourceFile(testSource));
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertEquals(3, sourceManager.getAllSourceFiles().size());
	}

	@Test
	public void testContainsNull() {
		assertFalse(sourceManager.containsSourceFile(null));
	}

	@Test
	public void basicContainsTest() throws LockException, IOException {
		assertTrue(sourceManager.containsSourceFile(source1));
		int txId = program.startTransaction("removing source1");
		try {
			assertTrue(sourceManager.removeSourceFile(source1));
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertFalse(sourceManager.containsSourceFile(source1));
		assertTrue(sourceManager.containsSourceFile(source2));
		assertTrue(sourceManager.containsSourceFile(source3));

		program.undo();

		assertTrue(sourceManager.containsSourceFile(source1));

		program.redo();

		assertFalse(sourceManager.containsSourceFile(source1));
	}

	@Test
	public void testUndoAddingSourceFile() throws LockException, IOException {
		SourceFile test = new SourceFile("/a/b/c.h");
		int txId = program.startTransaction("adding source file");
		try {
			sourceManager.addSourceFile(test);
		}
		finally {
			program.endTransaction(txId, true);
		}

		assertTrue(sourceManager.containsSourceFile(test));

		program.undo();

		assertFalse(sourceManager.containsSourceFile(test));

		program.redo();

		assertTrue(sourceManager.containsSourceFile(test));
	}

	@Test
	public void testGetUri() throws URISyntaxException {
		String path = "/src/test.c";
		URI uri = new URI("file", null, path, null);
		SourceFile testFile = new SourceFile(path);
		assertEquals(uri, testFile.getUri());
	}

	@Test
	public void testIdentifierDisplayString() {
		String path = "/src/test/file.c";
		HexFormat hexFormat = HexFormat.of();

		SourceFile sourceFile = new SourceFile(path, SourceFileIdType.MD5,
			hexFormat.parseHex("0123456789abcdef0123456789abcdef"));
		assertEquals(SourceFileIdType.MD5, sourceFile.getIdType());
		assertEquals(sourceFile.getIdAsString(), "0123456789abcdef0123456789abcdef");

		sourceFile = new SourceFile(path);
		assertEquals(SourceFileIdType.NONE, sourceFile.getIdType());
		assertEquals(StringUtils.EMPTY, sourceFile.getIdAsString());

		sourceFile = new SourceFile(path, SourceFileIdType.SHA1,
			hexFormat.parseHex("0123456789abcdef0123456789abcdef01234567"));
		assertEquals(SourceFileIdType.SHA1, sourceFile.getIdType());
		assertEquals("0123456789abcdef0123456789abcdef01234567", sourceFile.getIdAsString());

		sourceFile = new SourceFile(path, SourceFileIdType.SHA256,
			hexFormat.parseHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
		assertEquals(SourceFileIdType.SHA256, sourceFile.getIdType());
		assertEquals("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			sourceFile.getIdAsString());

		sourceFile = new SourceFile(path, SourceFileIdType.SHA512,
			hexFormat.parseHex(
				"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" +
					"abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
		assertEquals(
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" +
				"abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			sourceFile.getIdAsString());

		sourceFile = new SourceFile(path, SourceFileIdType.TIMESTAMP_64, Longs.toByteArray(0));
		assertEquals(SourceFileIdType.TIMESTAMP_64, sourceFile.getIdType());
		assertEquals("1970-01-01T00:00:00Z", sourceFile.getIdAsString());

		sourceFile = new SourceFile(path, SourceFileIdType.UNKNOWN, new byte[] { 0x12, 0x13 });
		assertEquals(SourceFileIdType.UNKNOWN, sourceFile.getIdType());
		assertEquals("1213", sourceFile.getIdAsString());
	}

	@Test
	public void testSamePathDifferentIdentifiers() throws LockException {
		HexFormat hexFormat = HexFormat.of();

		assertEquals(3, sourceManager.getAllSourceFiles().size());
		String path = "/src/test/file.c";
		SourceFile test1 = new SourceFile(path);
		SourceFile test2 = new SourceFile(path, SourceFileIdType.MD5,
			hexFormat.parseHex("0123456789abcdef0123456789abcdef"));
		SourceFile test3 =
			new SourceFile(path, SourceFileIdType.TIMESTAMP_64, Longs.toByteArray(0));

		assertNotEquals(test1, test2);
		assertNotEquals(test1, test3);
		assertNotEquals(test2, test3);

		assertFalse(sourceManager.containsSourceFile(test1));
		assertFalse(sourceManager.containsSourceFile(test2));
		assertFalse(sourceManager.containsSourceFile(test3));

		int txId = program.startTransaction("adding source file");
		try {
			sourceManager.addSourceFile(test1);
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceFile> sourceFiles = sourceManager.getAllSourceFiles();
		assertEquals(4, sourceFiles.size());

		assertTrue(sourceManager.containsSourceFile(test1));
		assertFalse(sourceManager.containsSourceFile(test2));
		assertFalse(sourceManager.containsSourceFile(test3));

		txId = program.startTransaction("adding source file");
		try {
			sourceManager.addSourceFile(test2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getAllSourceFiles();
		assertEquals(5, sourceFiles.size());

		assertTrue(sourceManager.containsSourceFile(test1));
		assertTrue(sourceManager.containsSourceFile(test2));
		assertFalse(sourceManager.containsSourceFile(test3));

		txId = program.startTransaction("adding source file");
		try {
			sourceManager.addSourceFile(test3);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getAllSourceFiles();
		assertEquals(6, sourceFiles.size());

		assertTrue(sourceManager.containsSourceFile(test1));
		assertTrue(sourceManager.containsSourceFile(test2));
		assertTrue(sourceManager.containsSourceFile(test3));

		//repeat adding test3
		txId = program.startTransaction("adding source file");
		try {
			sourceManager.addSourceFile(test3);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getAllSourceFiles();
		assertEquals(6, sourceFiles.size());

		assertTrue(sourceManager.containsSourceFile(test1));
		assertTrue(sourceManager.containsSourceFile(test2));
		assertTrue(sourceManager.containsSourceFile(test3));

		txId = program.startTransaction("removing source file");
		try {
			sourceManager.removeSourceFile(test2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getAllSourceFiles();
		assertEquals(5, sourceFiles.size());

		assertTrue(sourceManager.containsSourceFile(test1));
		assertFalse(sourceManager.containsSourceFile(test2));
		assertTrue(sourceManager.containsSourceFile(test3));

	}

	@Test
	public void testSameIdentifierDifferentPaths() throws LockException {
		HexFormat hexFormat = HexFormat.of();
		assertEquals(3, sourceManager.getAllSourceFiles().size());
		byte[] md5 = hexFormat.parseHex("0123456789abcdef0123456789abcdef");

		SourceFile test1 = new SourceFile("/src/file1.c", SourceFileIdType.MD5, md5);
		SourceFile test2 = new SourceFile("/src/file2.c", SourceFileIdType.MD5, md5);
		SourceFile test3 = new SourceFile("/src/file3.c", SourceFileIdType.MD5, md5);

		assertNotEquals(test1, test2);
		assertNotEquals(test1, test3);
		assertNotEquals(test2, test3);

		assertFalse(sourceManager.containsSourceFile(test1));
		assertFalse(sourceManager.containsSourceFile(test2));
		assertFalse(sourceManager.containsSourceFile(test3));

		int txId = program.startTransaction("adding source file");
		try {
			sourceManager.addSourceFile(test1);
		}
		finally {
			program.endTransaction(txId, true);
		}

		List<SourceFile> sourceFiles = sourceManager.getAllSourceFiles();
		assertEquals(4, sourceFiles.size());

		assertTrue(sourceManager.containsSourceFile(test1));
		assertFalse(sourceManager.containsSourceFile(test2));
		assertFalse(sourceManager.containsSourceFile(test3));

		txId = program.startTransaction("adding source file");
		try {
			sourceManager.addSourceFile(test2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getAllSourceFiles();
		assertEquals(5, sourceFiles.size());

		assertTrue(sourceManager.containsSourceFile(test1));
		assertTrue(sourceManager.containsSourceFile(test2));
		assertFalse(sourceManager.containsSourceFile(test3));

		txId = program.startTransaction("adding source file");
		try {
			sourceManager.addSourceFile(test3);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getAllSourceFiles();
		assertEquals(6, sourceFiles.size());

		assertTrue(sourceManager.containsSourceFile(test1));
		assertTrue(sourceManager.containsSourceFile(test2));
		assertTrue(sourceManager.containsSourceFile(test3));

		//repeat adding test3
		txId = program.startTransaction("adding source file");
		try {
			sourceManager.addSourceFile(test3);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getAllSourceFiles();
		assertEquals(6, sourceFiles.size());

		assertTrue(sourceManager.containsSourceFile(test1));
		assertTrue(sourceManager.containsSourceFile(test2));
		assertTrue(sourceManager.containsSourceFile(test3));

		txId = program.startTransaction("removing source file");
		try {
			sourceManager.removeSourceFile(test2);
		}
		finally {
			program.endTransaction(txId, true);
		}

		sourceFiles = sourceManager.getAllSourceFiles();
		assertEquals(5, sourceFiles.size());

		assertTrue(sourceManager.containsSourceFile(test1));
		assertFalse(sourceManager.containsSourceFile(test2));
		assertTrue(sourceManager.containsSourceFile(test3));

	}

	@Test
	public void testNoIdentifierNonNullArray() {
		SourceFile sourceFile =
			new SourceFile("/src/file.c", SourceFileIdType.NONE, new byte[] { 0x11, 0x22 });
		assertEquals("/src/file.c", sourceFile.getPath());
		assertEquals(SourceFileIdType.NONE, sourceFile.getIdType());

		// array passed to SourceFile constructor should be ignored
		assertTrue(Arrays.equals(new byte[0], sourceFile.getIdentifier()));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testBadMd5Length() {
		new SourceFile("/file.c", SourceFileIdType.MD5, new byte[] { 0x11, 0x22 });
	}

	@Test(expected = IllegalArgumentException.class)
	public void testMd5NullArray() {
		new SourceFile("/file.c", SourceFileIdType.MD5, null);
	}

	@Test(expected = NullPointerException.class)
	public void testAddingNullSourceFile() throws LockException {
		int txId = program.startTransaction("adding null SourceFile");
		try {
			sourceManager.addSourceFile(null);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = NullPointerException.class)
	public void testRemovingNullSourceFile() throws LockException {
		int txId = program.startTransaction("removing null source file");
		try {
			assertFalse(sourceManager.removeSourceFile(null));
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test(expected = NullPointerException.class)
	public void testConvertingNullArrayToLong() {
		SourceFileUtils.byteArrayToLong(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConvertingEmptyArrayToLong() {
		SourceFileUtils.byteArrayToLong(new byte[0]);
	}

	@Test
	public void testLongConversion() {
		long testLong = 0x0102030405060708L;
		byte[] testArray = new byte[] { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 };
		assertEquals(testLong, SourceFileUtils.byteArrayToLong(testArray));
		assertTrue(Arrays.equals(testArray, SourceFileUtils.longToByteArray(testLong)));
	}

	@Test
	public void testHexStringToByteArrayConversion() {
		assertTrue(Arrays.equals(new byte[0], SourceFileUtils.hexStringToByteArray(null)));
		assertTrue(
			Arrays.equals(new byte[0], SourceFileUtils.hexStringToByteArray(StringUtils.EMPTY)));
		assertTrue(Arrays.equals(new byte[0], SourceFileUtils.hexStringToByteArray("    ")));
		byte[] testArray = new byte[] { 0x00, 0x01, (byte) 0xaa, (byte) 0xff };
		assertTrue(Arrays.equals(testArray, SourceFileUtils.hexStringToByteArray("0001aaff")));
		assertTrue(Arrays.equals(testArray, SourceFileUtils.hexStringToByteArray("0001AAFF")));
		assertTrue(Arrays.equals(testArray, SourceFileUtils.hexStringToByteArray("0X0001AAFF")));
		assertTrue(Arrays.equals(testArray, SourceFileUtils.hexStringToByteArray("0x0001aaff")));
	}

	@Test
	public void testByteArrayToHexStringConversion() {
		assertEquals(StringUtils.EMPTY, SourceFileUtils.byteArrayToHexString(null));
		assertEquals(StringUtils.EMPTY, SourceFileUtils.byteArrayToHexString(new byte[0]));
		assertEquals("00112233445566778899aabbccddeeff",
			SourceFileUtils.byteArrayToHexString(new byte[] { 0x0, 0x11, 0x22, 0x33, 0x44, 0x55,
				0x66,
				0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd,
				(byte) 0xee, (byte) 0xff }));
	}

}
