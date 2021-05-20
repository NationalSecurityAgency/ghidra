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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Also see SymbolServerService2Test in the _Integration Tests module for tests that
 * decompress compressed pdb files.
 */
public class SymbolServerServiceTest extends AbstractGenericTest {
	private File temporaryDir;
	private File localSymbolStore1Root;
	private File localSymbolStore2Root;
	private LocalSymbolStore localSymbolStore1;
	private LocalSymbolStore localSymbolStore2;

	private File mkFile(File file) throws IOException {
		FileUtilities.checkedMkdirs(file.getParentFile());
		FileUtilities.writeStringToFile(file, "test");
		return file;
	}

	@Before
	public void setup() throws IOException {
		temporaryDir = createTempDirectory("symbolservers");
		localSymbolStore1Root = new File(temporaryDir, "symbols1");
		localSymbolStore2Root = new File(temporaryDir, "symbols2");
		LocalSymbolStore.create(localSymbolStore1Root, 1);
		LocalSymbolStore.create(localSymbolStore2Root, 1);

		localSymbolStore1 = new LocalSymbolStore(localSymbolStore1Root);
		localSymbolStore2 = new LocalSymbolStore(localSymbolStore2Root);
	}

	@Test
	public void test_Exact_AlreadyLocal() throws IOException, CancelledException {
		File pdbFile1 = mkFile(new File(localSymbolStore1Root, "file1.pdb/112233440/file1.pdb"));
		File pdbFile2 = mkFile(new File(localSymbolStore2Root, "file1.pdb/112233440/file1.pdb"));

		SymbolServerService symbolServerService = new SymbolServerService(localSymbolStore1,
			List.of(localSymbolStore1, localSymbolStore2));
		List<SymbolFileLocation> results =
			symbolServerService.find(SymbolFileInfo.fromValues("file1.pdb", "11223344", 0),
				TaskMonitor.DUMMY);

		assertEquals(2, results.size());

		File foundPdbFile1 = symbolServerService.getSymbolFile(results.get(0), TaskMonitor.DUMMY);
		File foundPdbFile2 = symbolServerService.getSymbolFile(results.get(1), TaskMonitor.DUMMY);

		assertEquals(pdbFile1, foundPdbFile1);
		assertEquals(pdbFile2, foundPdbFile2);
	}

	@Test
	public void test_AnyAge() throws IOException, CancelledException {
		// search for similar pdbs, across multiple storage servers
		mkFile(new File(localSymbolStore1Root, "file1.pdb/000000001/file1.pdb"));
		mkFile(new File(localSymbolStore1Root, "file1.pdb/112233441/file1.pdb"));
		mkFile(new File(localSymbolStore2Root, "file1.pdb/112233442/file1.pdb"));

		SymbolServerService symbolServerService =
			new SymbolServerService(localSymbolStore1, List.of(localSymbolStore2));
		List<SymbolFileLocation> results =
			symbolServerService.find(SymbolFileInfo.fromValues("file1.pdb", "11223344", 0),
				FindOption.of(FindOption.ANY_AGE), TaskMonitor.DUMMY);

		assertEquals(2, results.size());
		Set<String> uids = results.stream()
				.map(symbolFileLocation -> symbolFileLocation.getFileInfo().getUniqueName())
				.collect(Collectors.toSet());
		assertEquals(1, uids.size());
		assertTrue(uids.contains("11223344"));
	}

	@Test
	public void test_AnyUID() throws IOException, CancelledException {
		// search for similar pdbs, across multiple storage servers
		mkFile(new File(localSymbolStore1Root, "file2.pdb/000000001/file2.pdb"));
		mkFile(new File(localSymbolStore1Root, "file1.pdb/000000001/file1.pdb"));
		mkFile(new File(localSymbolStore1Root, "file1.pdb/112233441/file1.pdb"));
		mkFile(new File(localSymbolStore2Root, "file1.pdb/112233442/file1.pdb"));

		SymbolServerService symbolServerService =
			new SymbolServerService(localSymbolStore1, List.of(localSymbolStore2));
		List<SymbolFileLocation> results =
			symbolServerService.find(SymbolFileInfo.fromValues("file1.pdb", "11223344", 0),
				FindOption.of(FindOption.ANY_ID), TaskMonitor.DUMMY);

		assertEquals(3, results.size());
		Set<String> uids = results.stream()
				.map(symbolFileLocation -> symbolFileLocation.getFileInfo().getUniqueName())
				.collect(Collectors.toSet());
		assertEquals(2, uids.size());
		assertTrue(uids.contains("11223344"));
		assertTrue(uids.contains("00000000"));
	}

	@Test
	public void test_Remote() throws IOException, CancelledException {
		String payload = "testdummy";
		SymbolServerService symbolServerService =
			new SymbolServerService(localSymbolStore1,
				List.of(localSymbolStore2, new DummySymbolServer(payload)));
		SymbolFileInfo searchPdb = SymbolFileInfo.fromValues("file1.pdb", "11223344", 0);
		List<SymbolFileLocation> results =
			symbolServerService.find(searchPdb, FindOption.of(FindOption.ALLOW_REMOTE),
				TaskMonitor.DUMMY);

		assertEquals(1, results.size());
		assertTrue(results.get(0).isExactMatch(searchPdb));

		File pdbFile = symbolServerService.getSymbolFile(results.get(0), TaskMonitor.DUMMY);
		assertEquals(payload, Files.readString(pdbFile.toPath()));
	}

	@Test
	public void test_NoRemote() throws CancelledException {
		String payload = "testdummy";
		SymbolServerService symbolServerService =
			new SymbolServerService(localSymbolStore1, List.of(new DummySymbolServer(payload)));
		SymbolFileInfo searchPdb = SymbolFileInfo.fromValues("file1.pdb", "11223344", 0);
		List<SymbolFileLocation> results =
			symbolServerService.find(searchPdb, FindOption.NO_OPTIONS, TaskMonitor.DUMMY);

		assertEquals(0, results.size());
	}

}
