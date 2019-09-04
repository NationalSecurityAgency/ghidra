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
package ghidra.program.database.mem;

import static org.junit.Assert.*;

import java.io.*;
import java.util.List;

import org.junit.*;

import db.*;
import db.buffers.BufferFile;
import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.framework.Application;
import ghidra.framework.store.db.PrivateDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

public class FileBytesTest extends AbstractGenericTest {

	// Use of small buffer size will not exercise use of indexed ChainedBuffer,
	// therefor those tests which need to exercise this should use a size which
	// exceeds 16-KBytes.
	private static final int MAX_BUFFER_SIZE_FOR_TESTING = 200;

	private Program program;
	private Memory mem;
	private int transactionID;
	private File tempDir;

	@Test
	public void testStoreAndRetrieveFileBytes() throws Exception {
		int dataSize = MAX_BUFFER_SIZE_FOR_TESTING / 2;
		FileBytes fileBytes = createFileBytes("testFile", dataSize);

		byte[] outBytes = new byte[200];
		assertEquals("testFile", fileBytes.getFilename());
		assertEquals(0L, fileBytes.getFileOffset());
		assertEquals(dataSize, fileBytes.getSize());
		int n = fileBytes.getOriginalBytes(0L, outBytes);
		assertEquals(dataSize, n);
		for (int i = 0; i < dataSize; i++) {
			assertEquals("Byte[" + i + "]", i, outBytes[i]);
		}
	}

	@Test
	public void testRetrieveAfterSavingAndReopeningProgram() throws Exception {
		int dataSize = MAX_BUFFER_SIZE_FOR_TESTING / 2;
		FileBytes fileBytes = createFileBytes("testFile", dataSize);

		byte[] outBytes = new byte[200];

		saveAndRestoreProgram("A");

		List<FileBytes> list = program.getMemory().getAllFileBytes();
		fileBytes = list.get(0);

		assertEquals("testFile", fileBytes.getFilename());
		assertEquals(0L, fileBytes.getFileOffset());
		assertEquals(dataSize, fileBytes.getSize());
		int n = fileBytes.getOriginalBytes(0L, outBytes);
		assertEquals(100, n);
		for (int i = 0; i < dataSize; i++) {
			assertEquals("Byte[" + i + "]", i, outBytes[i]);
		}
	}

	@Test
	public void testRequiresMultipleBuffers() throws Exception {
		int dataSize = MAX_BUFFER_SIZE_FOR_TESTING + MAX_BUFFER_SIZE_FOR_TESTING / 2;
		FileBytes fileBytes = createFileBytes("testFile", dataSize);

		saveAndRestoreProgram("A");

		byte[] outBytes = new byte[400];
		List<FileBytes> list = program.getMemory().getAllFileBytes();
		fileBytes = list.get(0);

		assertEquals("testFile", fileBytes.getFilename());
		assertEquals(0L, fileBytes.getFileOffset());
		assertEquals(dataSize, fileBytes.getSize());
		int n = fileBytes.getOriginalBytes(0L, outBytes);
		assertEquals(dataSize, n);
		for (int i = 0; i < dataSize; i++) {
			assertEquals("Byte[" + i + "]", (byte) i, outBytes[i]);
		}
		DBBuffer[] buffers = (DBBuffer[]) getInstanceField("originalBuffers", fileBytes);
		assertEquals(2, buffers.length);
		assertEquals(MAX_BUFFER_SIZE_FOR_TESTING, buffers[0].length());
	}

	@Test
	public void testCreateMultipleFileBytes() throws Exception {
		createFileBytes("file1", 10);
		createFileBytes("file2", 20);
		createFileBytes("file3", 30);

		saveAndRestoreProgram("A");
		List<FileBytes> fileBytesList = mem.getAllFileBytes();
		assertEquals(3, fileBytesList.size());
		assertEquals("file1", fileBytesList.get(0).getFilename());
		assertEquals(10, fileBytesList.get(0).getSize());
		assertEquals("file2", fileBytesList.get(1).getFilename());
		assertEquals(20, fileBytesList.get(1).getSize());
		assertEquals("file3", fileBytesList.get(2).getFilename());
		assertEquals(30, fileBytesList.get(2).getSize());
	}

	@Test
	public void testDeleteFileBytesDescriptors() throws Exception {
		createFileBytes("file1", 10);
		createFileBytes("file2", 20);
		createFileBytes("file3", 30);

		saveAndRestoreProgram("A");
		List<FileBytes> fileBytes = mem.getAllFileBytes();

		mem.deleteFileBytes(fileBytes.get(1));

		saveAndRestoreProgram("B");
		List<FileBytes> fileBytesList = mem.getAllFileBytes();
		assertEquals(2, fileBytesList.size());
		assertEquals("file1", fileBytesList.get(0).getFilename());
		assertEquals(10, fileBytesList.get(0).getSize());
		assertEquals("file3", fileBytesList.get(1).getFilename());
		assertEquals(30, fileBytesList.get(1).getSize());
	}

	@Test
	public void testGetByte() throws Exception {
		FileBytes fileBytes = createFileBytes("file1", 10);
		assertEquals(5, fileBytes.getOriginalByte(5));
	}

	@Test
	public void testGetLayeredByte() throws Exception {
		FileBytes fileBytes = createFileBytes("file1", 10);
		incrementFileBytes(fileBytes, 0, 10);

		// check that the layered bytes are changed, but you can still get the originals
		for (int i = 0; i < 10; i++) {
			assertEquals(i, fileBytes.getOriginalByte(i));
			assertEquals(i + 1, fileBytes.getModifiedByte(i));
		}

	}

	private void incrementFileBytes(FileBytes fileBytes, int offset, int n) throws IOException {
		for (int i = offset; i < offset + n; i++) {
			fileBytes.putByte(i, (byte) (fileBytes.getModifiedByte(i) + 1));
		}
	}

	@Test
	public void testGetLayeredBytes() throws Exception {
		FileBytes fileBytes = createFileBytes("file1", 10);
		incrementFileBytes(fileBytes, 0, 10);

		// check that the layered bytes are changed, but you can still get the originals
		byte[] original = new byte[10];
		byte[] modified = new byte[10];
		fileBytes.getOriginalBytes(0, original);
		fileBytes.getModifiedBytes(0, modified);
		for (int i = 0; i < 10; i++) {
			assertEquals(i, original[i]);
			assertEquals(i + 1, modified[i]);
		}
	}

	@Test
	public void testGetLayeredBytesAfterUndo() throws Exception {
		// NOTE: need to induce use of indexed ChainedBuffer
		FileBytesAdapter.setMaxBufferSize(FileBytesAdapter.MAX_BUF_SIZE);
		FileBytes fileBytes = createFileBytes("file1", 20000);

		program.endTransaction(transactionID, true);
		transactionID = program.startTransaction("modify");

		incrementFileBytes(fileBytes, 0, 10);
		incrementFileBytes(fileBytes, 18999, 10);

		// undo layered buffer changes
		program.endTransaction(transactionID, true);
		program.undo();
		transactionID = program.startTransaction("resume");

		// check that the layered bytes are unchanged from the originals
		assertEquals(1, fileBytes.getOriginalByte(1));
		assertEquals(1, fileBytes.getModifiedByte(1));

		byte b = (byte) 19000;
		assertEquals(b, fileBytes.getOriginalByte(19000));
		assertEquals(b, fileBytes.getModifiedByte(19000));
	}

	@Test
	public void testGetLayeredBytesAfterUndoRedo() throws Exception {
		// NOTE: need to induce use of indexed ChainedBuffer
		FileBytesAdapter.setMaxBufferSize(FileBytesAdapter.MAX_BUF_SIZE);
		FileBytes fileBytes = createFileBytes("file1", 20000);

		program.endTransaction(transactionID, true);
		transactionID = program.startTransaction("modify");

		incrementFileBytes(fileBytes, 0, 10);
		incrementFileBytes(fileBytes, 18999, 10);

		// undo layered buffer changes
		program.endTransaction(transactionID, true);
		program.undo();
		program.redo();
		transactionID = program.startTransaction("resume");

		// check that the layered bytes are unchanged from the originals
		assertEquals(1, fileBytes.getOriginalByte(1));
		assertEquals(2, fileBytes.getModifiedByte(1));

		byte b = (byte) 19000;
		assertEquals(b, fileBytes.getOriginalByte(19000));
		assertEquals((byte) (b + 1), fileBytes.getModifiedByte(19000));
	}

	private FileBytes createFileBytes(String name, int size) throws Exception {
		byte[] bytes = new byte[size];
		for (int i = 0; i < size; i++) {
			bytes[i] = (byte) i;
		}
		try (ByteArrayInputStream is = new ByteArrayInputStream(bytes)) {
			return mem.createFileBytes(name, 0, size, is, TaskMonitor.DUMMY);
		}
	}

	private void saveAndRestoreProgram(String dbName) throws Exception {
		program.endTransaction(transactionID, true);
		PrivateDatabase privateDatabase = saveProgram(program, dbName);
		program.release(this);
		program = restoreProgram(privateDatabase);

		mem = program.getMemory();
		transactionID = program.startTransaction("test");
	}

	private PrivateDatabase saveProgram(Program program, String dbName) throws Exception {
		File dbDir = new File(tempDir, dbName);

		DBHandle dbh = ((ProgramDB) program).getDBHandle();
		BufferFile bfile = PrivateDatabase.createDatabase(dbDir, null, dbh.getBufferSize());
		dbh.saveAs(bfile, true, TaskMonitor.DUMMY);
		return new PrivateDatabase(dbDir);
	}

	private Program restoreProgram(PrivateDatabase db) throws Exception {
		DBHandle dbh = db.open(TaskMonitor.DUMMY);
		return new ProgramDB(dbh, DBConstants.UPDATE, null, this);
	}

	@Before
	public void setUp() throws Exception {
		tempDir = createTempDirectory("FileBytesTest");
		FileBytesAdapter.setMaxBufferSize(MAX_BUFFER_SIZE_FOR_TESTING);
		Language language = getLanguage("Toy:BE:64:default");
		CompilerSpec compilerSpec = language.getDefaultCompilerSpec();
		program = new ProgramDB("Test", language, compilerSpec, this);

		mem = program.getMemory();
		transactionID = program.startTransaction("Test");
	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	private Language getLanguage(String languageName) throws Exception {

		ResourceFile ldefFile = Application.getModuleDataFile("Toy", "languages/toy.ldefs");
		if (ldefFile != null) {
			LanguageService languageService = DefaultLanguageService.getLanguageService(ldefFile);
			Language language = languageService.getLanguage(new LanguageID(languageName));
			return language;
		}
		throw new LanguageNotFoundException("Unsupported test language: " + languageName);
	}
}
