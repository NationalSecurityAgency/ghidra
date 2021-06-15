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
package pdb.symbolserver;

import static org.junit.Assert.*;

import java.util.List;

import java.io.File;
import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Test searching for symbol files in a local directory structure.
 * <p>
 * Directory level 1, 2 are MS compatible layouts of pdb symbol files.
 * Directory level 0 is a ghidra-ism where pdb symbol files can
 * be found in a un-organized directory with non-exact file names.
 * <p>
 * Testing level 0 searching is a TODO item because creating test
 * files that can be parsed isn't possible right now. (level 1, 2
 * directories can skip parsing the file since the guid/age is
 * in the path) 
 */
public class LocalSymbolServerTest extends AbstractGenericTest {

	private File temporaryDir;

	private File mkFile(File file) throws IOException {
		FileUtilities.checkedMkdirs(file.getParentFile());
		FileUtilities.writeStringToFile(file, "test");
		return file;
	}

	@Before
	public void setup() throws IOException {
		temporaryDir = createTempDirectory("localsymbolserver");
	}

	@Test
	public void testCreate_Level0() throws IOException {
		File root = new File(temporaryDir, "symbols");
		LocalSymbolStore.create(root, 0);

		assertTrue("Should not create files", root.list().length == 0);
	}

	@Test
	public void testCreate_Level1() throws IOException {
		File root = new File(temporaryDir, "symbols");
		LocalSymbolStore.create(root, 1);

		assertTrue("Pingme should exist", new File(root, "pingme.txt").exists());
		assertTrue("Admin dir should exist", new File(root, "000admin").exists());
		assertFalse("Index2 should not exist", new File(root, "index2.txt").exists());
	}

	@Test
	public void testCreate_Level2() throws IOException {
		File root = new File(temporaryDir, "symbols");
		LocalSymbolStore.create(root, 2);

		assertTrue("Pingme should exist", new File(root, "pingme.txt").exists());
		assertTrue("Admin dir should exist", new File(root, "000admin").exists());
		assertTrue("Index2 should exist", new File(root, "index2.txt").exists());
	}

	@Test
	public void findExact_Level1() throws IOException {
		File root = new File(temporaryDir, "symbols");
		LocalSymbolStore.create(root, 1);
		LocalSymbolStore localSymbolStore = new LocalSymbolStore(root);

		File pdbFile = mkFile(new File(root, "file1.pdb/112233445/file1.pdb"));
		mkFile(new File(root, "file1.pdb/112233446/file1.pdb"));

		List<SymbolFileLocation> results =
			localSymbolStore.find(SymbolFileInfo.fromValues("file1.pdb", "11223344", 5),
				FindOption.NO_OPTIONS, TaskMonitor.DUMMY);

		assertEquals(1, results.size());

		String resultLocation = localSymbolStore.getFileLocation(results.get(0).getPath());
		assertEquals(pdbFile.getPath(), resultLocation);
	}

	@Test
	public void findAnyAges_Level1() throws IOException {
		// find pdbs with the same UID, but any AGE 
		File root = new File(temporaryDir, "symbols");
		LocalSymbolStore.create(root, 1);
		LocalSymbolStore localSymbolStore = new LocalSymbolStore(root);

		mkFile(new File(root, "file1.pdb/112233445/file1.pdb"));
		mkFile(new File(root, "file1.pdb/112233446/file1.pdb"));
		mkFile(new File(root, "file1.pdb/112233450/file1.pdb"));

		List<SymbolFileLocation> results =
			localSymbolStore.find(SymbolFileInfo.fromValues("file1.pdb", "11223344", 0),
				FindOption.of(FindOption.ANY_AGE), TaskMonitor.DUMMY);

		assertEquals(2, results.size());
		assertFalse(results.stream()
				.map(symbolFileLocation -> symbolFileLocation.getFileInfo().getUniqueName())
				.anyMatch(s -> !s.equals("11223344")));
	}

	@Test
	public void findAnyUIDs_Level1() throws IOException {
		File root = new File(temporaryDir, "symbols");
		LocalSymbolStore.create(root, 1);
		LocalSymbolStore localSymbolStore = new LocalSymbolStore(root);

		mkFile(new File(root, "file1.pdb/112233400/file1.pdb"));
		mkFile(new File(root, "file1.pdb/112233410/file1.pdb"));
		mkFile(new File(root, "file1.pdb/112233420/file1.pdb"));

		List<SymbolFileLocation> results =
			localSymbolStore.find(SymbolFileInfo.fromValues("file1.pdb", "11223344", 0),
				FindOption.of(FindOption.ANY_ID), TaskMonitor.DUMMY);

		assertEquals(3, results.size());
	}

	@Test
	public void findExact_Level2() throws IOException {
		File root = new File(temporaryDir, "symbols");
		LocalSymbolStore.create(root, 2);
		LocalSymbolStore localSymbolStore = new LocalSymbolStore(root);

		File similarPdbFile1 = mkFile(new File(root, "fi/file1.pdb/112233445/file1.pdb"));
		mkFile(new File(root, "fi/file1.pdb/112233446/file1.pdb"));

		List<SymbolFileLocation> results =
			localSymbolStore.find(SymbolFileInfo.fromValues("file1.pdb", "11223344", 5),
				FindOption.NO_OPTIONS, TaskMonitor.DUMMY);

		assertEquals(1, results.size());

		String resultLocation = localSymbolStore.getFileLocation(results.get(0).getPath());
		assertEquals(similarPdbFile1.getPath(), resultLocation);
	}

	@Test
	public void giveFile_Level0() throws IOException {
		File root = new File(temporaryDir, "symbols");
		LocalSymbolStore.create(root, 0);

		LocalSymbolStore localSymbolStore = new LocalSymbolStore(root);

		File file1 = mkFile(new File(temporaryDir, "file1.pdb"));
		localSymbolStore.giveFile(SymbolFileInfo.fromValues("file1.pdb", "11223344", 0), file1,
			"file1.pdb", TaskMonitor.DUMMY);

		assertFalse(file1.exists());

		// can't search for the pdb file because a level0 LocalSymbolStore would
		// need to open up any 'pdb' files it finds to read the guid/id and age,
		// and we can't create good pdbs right now that would enable this.

		File expectedFile = new File(root, "file1.pdb");
		assertTrue(expectedFile.exists());
	}

	@Test
	public void giveFile_Level1() throws IOException {
		File root = new File(temporaryDir, "symbols");
		LocalSymbolStore.create(root, 1);
		LocalSymbolStore localSymbolStore = new LocalSymbolStore(root);

		File file1 = mkFile(new File(temporaryDir, "file1.pdb"));
		localSymbolStore.giveFile(SymbolFileInfo.fromValues("file1.pdb", "11223344", 0), file1,
			"file1.pdb", TaskMonitor.DUMMY);

		assertFalse(file1.exists());

		List<SymbolFileLocation> results =
			localSymbolStore.find(SymbolFileInfo.fromValues("file1.pdb", "11223344", 0),
				FindOption.NO_OPTIONS, TaskMonitor.DUMMY);
		assertEquals(1, results.size());
		assertEquals("file1.pdb/112233440/file1.pdb", results.get(0).getPath());
		assertEquals("11223344", results.get(0).getFileInfo().getUniqueName());
		assertEquals(0, results.get(0).getFileInfo().getIdentifiers().getAge());
	}

	@Test
	public void giveFile_Level2() throws IOException {
		File root = new File(temporaryDir, "symbols");
		LocalSymbolStore.create(root, 1);
		LocalSymbolStore localSymbolStore = new LocalSymbolStore(root);

		File file1 = mkFile(new File(temporaryDir, "file1.pdb"));
		localSymbolStore.giveFile(SymbolFileInfo.fromValues("file1.pdb", "11223344", 0), file1,
			"file1.pdb", TaskMonitor.DUMMY);

		assertFalse(file1.exists());

		List<SymbolFileLocation> results =
			localSymbolStore.find(SymbolFileInfo.fromValues("file1.pdb", "11223344", 0),
				FindOption.NO_OPTIONS, TaskMonitor.DUMMY);
		assertEquals(1, results.size());
		assertEquals("file1.pdb/112233440/file1.pdb", results.get(0).getPath());
		assertEquals("11223344", results.get(0).getFileInfo().getUniqueName());
		assertEquals(0, results.get(0).getFileInfo().getIdentifiers().getAge());
	}
}
