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

import java.util.List;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FilenameUtils;
import org.junit.Before;
import org.junit.Test;

import com.google.common.io.BaseEncoding;

import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Tests for Pdb SymbolServer stuff that need to be in the Integration module because they depend 
 * on FileFormat's file system stuff to decompress .cab files
 */
public class SymbolServerService2Test extends AbstractGhidraHeadedIntegrationTest {
	private File temporaryDir;
	private File localSymbolStore1Root;
	private LocalSymbolStore localSymbolStore1;

	// Bytes for a very small .cab file that contains a singleton file named 'test.pdb' with
	// contents of "test"
	byte[] smallCabFileBytes = BaseEncoding.base16()
			.decode(("4d5343460000000055000000000000002c000000000000000301010001" +
				"00000000000000450000000100010004000000000000000000a248bc5c2000746573742e7064620" +
				"066652e4908000400434b2b492d2e0100").toUpperCase());

	private File mkFile(File file, byte[] bytes) throws IOException {
		FileUtilities.checkedMkdirs(file.getParentFile());
		FileUtilities.writeBytes(file, bytes);
		return file;
	}

	@Before
	public void setup() throws IOException {
		temporaryDir = createTempDirectory("symbolservers");
		localSymbolStore1Root = new File(temporaryDir, "symbols1");
		LocalSymbolStore.create(localSymbolStore1Root, 1);

		localSymbolStore1 = new LocalSymbolStore(localSymbolStore1Root);
	}

	@Test
	public void testLocalCab() throws IOException, CancelledException {
		mkFile(new File(localSymbolStore1Root, "test.pdb/112233441/test.pd_"), smallCabFileBytes);

		SymbolServerService symbolServerService =
			new SymbolServerService(localSymbolStore1, List.of());
		List<SymbolFileLocation> results =
			symbolServerService.find(SymbolFileInfo.fromValues("test.pdb", "11223344", 1),
				FindOption.NO_OPTIONS, TaskMonitor.DUMMY);

		assertEquals(1, results.size());
		assertEquals("test.pd_", FilenameUtils.getName(results.get(0).getPath()));

		File pdbFile = symbolServerService.getSymbolFile(results.get(0), TaskMonitor.DUMMY);
		assertEquals("test\n" /* extra \n because FileUtilities.getText() adds it */,
			FileUtilities.getText(pdbFile));

		// search again and we should only find the now decompressed pdb file
		List<SymbolFileLocation> results2 =
			symbolServerService.find(SymbolFileInfo.fromValues("test.pdb", "11223344", 1),
				FindOption.NO_OPTIONS, TaskMonitor.DUMMY);

		assertEquals(1, results2.size());
		assertEquals("test.pdb", FilenameUtils.getName(results2.get(0).getPath()));
	}

	@Test
	public void testRemoteCab() throws IOException, CancelledException {

		SymbolServerService symbolServerService =
			new SymbolServerService(localSymbolStore1,
				List.of(new DummySymbolServer(smallCabFileBytes, true)));

		List<SymbolFileLocation> results =
			symbolServerService.find(SymbolFileInfo.fromValues("test.pdb", "11223344", 1),
				FindOption.of(FindOption.ALLOW_REMOTE), TaskMonitor.DUMMY);

		assertEquals(1, results.size());
		System.out.println(results.get(0).getLocationStr());

		File pdbFile = symbolServerService.getSymbolFile(results.get(0), TaskMonitor.DUMMY);
		assertEquals("test\n" /* extra \n because FileUtilities.getText() adds it */,
			FileUtilities.getText(pdbFile));
	}

	@Test
	public void testRemoteCabAlreadyExistLocal() throws IOException, CancelledException {

		SymbolServerService symbolServerService =
			new SymbolServerService(localSymbolStore1,
				List.of(new DummySymbolServer(smallCabFileBytes, true)));

		List<SymbolFileLocation> results =
			symbolServerService.find(SymbolFileInfo.fromValues("test.pdb", "11223344", 1),
				FindOption.of(FindOption.ALLOW_REMOTE), TaskMonitor.DUMMY);

		assertEquals(1, results.size());
		System.out.println(results.get(0).getLocationStr());

		// cheese the file into the local symbol store after the remote file has been found
		// but before it has been downloaded
		mkFile(new File(localSymbolStore1Root, "test.pdb/112233441/test.pdb"),
			"nottest".getBytes());

		// normally this would download the remote file and decompress it
		File pdbFile = symbolServerService.getSymbolFile(results.get(0), TaskMonitor.DUMMY);

		// ensure that the original file wasn't overwritten by the new file
		assertEquals("nottest\n" /* extra \n because FileUtilities.getText() adds it */,
			FileUtilities.getText(pdbFile));
	}
}
