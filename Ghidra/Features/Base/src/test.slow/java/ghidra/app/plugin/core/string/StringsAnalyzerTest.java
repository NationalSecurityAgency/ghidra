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
package ghidra.app.plugin.core.string;

import static org.junit.Assert.*;

import java.io.*;
import java.util.*;

import org.junit.*;

import generic.jar.ResourceFile;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.Application;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class StringsAnalyzerTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramBuilder builder;
	private TaskMonitor monitor = new TaskMonitorAdapter();

	private static final Map<String, Map<String, String>> programBytesMap = new HashMap<>();
	private static final Map<String, MemBlockParams[]> programMemBlocksMap = new HashMap<>();

	static class MemBlockParams {
		String startAddress;
		int blockSize;
		boolean read, write, execute;

		public MemBlockParams(String address, int size) {
			startAddress = address;
			blockSize = size;

			read = true;
			write = true;
			execute = false;
		}

		public MemBlockParams(String address, int size, boolean r, boolean w, boolean e) {
			startAddress = address;
			blockSize = size;

			read = r;
			write = w;
			execute = e;
		}

		public String getStartAddress() {
			return startAddress;
		}

		public int getBlockSize() {
			return blockSize;
		}

		public boolean getRead() {
			return read;
		}

		public boolean getWrite() {
			return write;
		}

		public boolean getExecute() {
			return execute;
		}
	}

	static {

		// Bytes for notepad.exe
		Map<String, String> tempMap = new HashMap<>();
		tempMap.put("0x10013b1",
			"4e 00 70 00 53 00 61 00 76 00 65 00 44 00 69 00 61 00 6c 00 6f 00 67 00 00 00 00 00 " +
				"6e 6f 74 65 70 61 64 2e 63 68 6d 00 52 65 67 69 73 74 65 72 50 65 6e 41 70 70 " +
				"00 00 25 00 64 00");
		tempMap.put("0x1008019", "4e 00 6f 00 74 00 65 00 70 00 61 00 64 00 00 00");
		tempMap.put("0x100d613",
			"4e 00 6f 00 77 00 20 00 50 00 72 00 69 00 6e 00 74 00 69 00 6e 00 67 00 00 00 00 " +
				"00 00 00 81 00 02");
		tempMap.put("0x100d72f", "50 00 61 00 70 00 65 00 72 00 00 00 00 00 00 00 02");
		tempMap.put("0x100daab",
			"50 00 72 00 65 00 76 00 69 00 65 00 77 00 00 00 00 00 06 00 00 50");
		programBytesMap.put("notepad.exe", tempMap);

		MemBlockParams[] notepadMemBlocks = new MemBlockParams[1];
		notepadMemBlocks[0] = new MemBlockParams("0x10013a0", 51020);
		programMemBlocksMap.put("notepad.exe", notepadMemBlocks);

		// Bytes for libopencoreplayer.so
		tempMap = new HashMap<>();
		tempMap.put("0xa71756c2", "00 00 74 6e 69 68 74 78 65 74 4c 09 00 00 f8 14 00");
		tempMap.put("0xa717fa48", "64 65 76 69 63 65 00 00 00 00 00 00 00 00 00 00 00");
		tempMap.put("0xa718025c", "76 69 64 65 6f 2f 64 65 63 6f 64 65 72 00 00 00");
		tempMap.put("0xa71802a8", "70 6c 61 79 65 72 00");
		tempMap.put("0xa7192c00", "4f 4d 58 41 61 63 44 65 63 00 00");
		tempMap.put("0xa7192fa0", "72 42 42 41 53 65 70 7a 4e 6e 4c 72");
		tempMap.put("0xa71956a0", "68 65 69 67 68 74 00 00 00 00 00");
		tempMap.put("0xa7195fd4", "50 56 46 4d 56 69 64 65 6f 4d 49 4f 00 00 00 00 50");
		tempMap.put("0xa7196ee8", "73 65 74 20 74 6f 20 69 6e 76 61 6c 69 64 20 6d 6f 64 65 " +
			"20 28 25 64 29 00 00 00 00");
		tempMap.put("0xa7197304", "50 4c 41 59 45 52 5f 51 55 49 54 00");
		tempMap.put("0xa71978d4", "28 00 00 00 4c 00 00 00 69 00 00 00 6e 00 00 00 75 00 00 " +
			"00 78 00 00 00 3b 00 00 00 55 00 00 00 3b 00 00 00 41 00 00 00 6e 00 00 00 64 00 " +
			"00 00 72 00 00 00 6f 00 00 00 69 00 00 00 64 00 00 00 20 00 00 00 31 00 00 00 2e " +
			"00 00 00 30 00 00 00 29 00 00 00 28 00 00 00 41 00 00 00 6e 00 00 00 64 00 00 00 " +
			"72 00 00 00 6f 00 00 00 69 00 00 00 64 00 00 00 4d 00 00 00 65 00 00 00 64 00 00 " +
			"00 69 00 00 00 61 00 00 00 50 00 00 00 6c 00 00 00 61 00 00 00 79 00 00 00 65 00 " +
			"00 00 72 00 00 00 20 00 00 00 31 00 00 00 2e 00 00 00 30 00 00 00 29 00 00 00 00 " +
			"00 00 50 56");
		tempMap.put("0xa7198120", "64 72 6d 2f 64 75 72 61 74 69 6f 6e 00 00 00 00");
		programBytesMap.put("libopencoreplayer.so", tempMap);

		MemBlockParams[] libopencoreMemBlocks = new MemBlockParams[1];
		libopencoreMemBlocks[0] = new MemBlockParams("0xa71756b0", 150000);
		programMemBlocksMap.put("libopencoreplayer.so", libopencoreMemBlocks);

		// Bytes for msvidctl.dll
		tempMap = new HashMap<>();
		tempMap.put("0x5a29b0c0", "00 00 6d 63 69 53 65 6e 64 43 6f 6d 6d 61 6e 64 57 00 00 00");
		tempMap.put("0x5a2afc20", "4b 65 79 50 72 65 73 73 ff ff ff ff ff");
		tempMap.put("0x5a2b00e4", "46 72 69 65 6e 64 6c 79 4e 61 6d 65 ff ff ff");
		tempMap.put("0x5a2b0384", "52 65 6d 6f 74 65 57 72 69 74 65 57 ff ff");
		tempMap.put("0x5a2b07a6",
			"5f 2b 52 65 6c 65 61 73 65 42 6f 75 6e 64 4f 62 6a 65 63 " + "74 73 57 60 09 00 00");
		tempMap.put("0x5a2b4ae2", "00 00 f4 18 00 00 12 38 57 44 49 4d 53 56 69 64 4f 75 74 " +
			"70 75 74 44 65 76 69 63 65 57 57 28 23 00 00");
		tempMap.put("0x5a2b5275", "00 3f 79 63 75 72 72 65 6e 74 49 6d 61 67 65 28 23");
		tempMap.put("0x5a2b598d", "30 44 4c 56 69 64 65 6f 57 57 57 50 2d 00 00 ec");
		tempMap.put("0x5a2b626e",
			"5d 6b 43 6f 6e 74 65 6e 74 42 65 63 6f 6d 69 6e 67 53 74 " + "61 6c 65 2c 33 00");
		tempMap.put("0x5a2b7720", "0e 00 43 6f 6d 70 6f 6e 65 6e 74 20 54 79 70 65 2c 00 4c " +
			"61 6e 67 75 61 67 65 20 49 64 65 6e 74 69 66 69 65 72 20 66 69 65 72 20 66 6f 72 " +
			"20 44 65 73 63 72 69 70 74 69 6f 6e 20 4c 61 6e 67 75 61 67 65 57 57 10 00");
		tempMap.put("0x5a2b891a", "53 65 74 20 74 68 65 20 73 69 6e 6b 20 66 69 6c 74 65 72 " +
			"20 28 43 4c 53 49 44 29 57 57 57 09 00");
		tempMap.put("0x5a2b90b2", "4d 53 20 56 69 64 65 6f 20 43 6f 6e 74 72 6f 6c 20 49 6e " +
			"74 65 72 66 61 63 65 3b 00 4d 53 20");
		tempMap.put("0x5a2cc2fa",
			"4e 3b 45 6e 75 6d 4d 65 64 69 61 54 79 70 65 73 57 57 30 " + "2a 00 00");
		tempMap.put("0x5a2cdafe", "4c 6f 6e 67 69 74 75 64 65 20 69 6e 20 74 65 6e 74 68 73 " +
			"20 6f 66 20 61 20 64 65 67 72 65 65 57 57 57 1d 00");
		tempMap.put("0x5a2cdcd2", "52 65 74 75 72 6e 73 20 61 6e 20 65 6e 75 6d 65 72 61 74 " +
			"6f 72 20 66 6f 72 20 54 75 6e 69 6e 67 20 53 70 61 63 65 73 20 61 63 63 65 70 74 " +
			"65 64 20 62 79 20 74 68 69 73 20 74 75 6e 65 72 13 00");
		programBytesMap.put("msvidctl.dll", tempMap);

		MemBlockParams[] msvidctlMemBlocks = new MemBlockParams[1];
		msvidctlMemBlocks[0] = new MemBlockParams("0x5a2afc10", 208000);
		programMemBlocksMap.put("msvidctl.dll", msvidctlMemBlocks);

		// Bytes for finder.exe
		tempMap = new HashMap<>();
		tempMap.put("0x300010cc", "0d 0a 00 00 54 4c 4f 53 53 20 65 72 72 6f 72 0d 0a 00 00 " +
			"00 53 49 4e 47 20 65 72 72 6f 72 0d 0a 00");
		tempMap.put("0x30001348", "4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b " +
			"2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 00 00 00 00 0a");
		tempMap.put("0x300013ac", "47 65 74 4c 61 73 74 41 63 74 69 76 65 50 6f 70 75 70 00");
		tempMap.put("0x300013dc", "75 73 65 72 33 32 2e 64 6c 6c 00");
		programBytesMap.put("finder.exe", tempMap);

		MemBlockParams[] finderMemBlocks = new MemBlockParams[1];
		finderMemBlocks[0] = new MemBlockParams("0x300010b0", 1000);
		programMemBlocksMap.put("finder.exe", finderMemBlocks);

		// Bytes for xtraceroute
		tempMap = new HashMap<>();
		tempMap.put("0x08057b60", "41 6e 67 75 69 6c 6c 61");
		tempMap.put("0x08057fb0",
			"42 6f 73 6e 69 61 20 61 6e 64 20 48 65 72 7a 65 67 6f 77 " + "69 6e 61");
		tempMap.put("0x08057e2c", "33 33 33 33 33 13 48 40 b8 1e 85 eb 51 38 30 40 41 54");
		tempMap.put("0x0805bc6c", "4b 69 6e 67 64 6f 6d 20 6f 66 20 53 77 65 64 65 6e");
		tempMap.put("0x00000000",
			"00 47 43 43 3a 20 28 47 4e 55 29 20 33 2e 32 20 32 30 30 " +
				"32 30 37 32 30 20 28 52 65 64 20 48 61 74 20 4c 69 6e 75 78 20 52 61 77 68 69 " +
				"64 65 20 33 2e 32 2d 30 2e 31 29 00 00");
		tempMap.put("0x000002fc",
			"47 43 43 3a 20 28 47 4e 55 29 20 33 2e 32 20 32 30 30 32 " +
				"30 37 32 30 20 28 52 65 64 20 48 61 74 20 4c 69 6e 75 78 20 52 61 77 68 69 64 " +
				"65 20 33 2e 32 2d 30 2e 31 2e 31 29 00");
		programBytesMap.put("xtraceroute", tempMap);

		MemBlockParams[] xtracerouteMemBlocks = new MemBlockParams[2];
		xtracerouteMemBlocks[0] = new MemBlockParams("0x08057900", 30000, true, false, false);
		xtracerouteMemBlocks[1] = new MemBlockParams("0x00000000", 1000, false, false, false);
		programMemBlocksMap.put("xtraceroute", xtracerouteMemBlocks);

		// Bytes for alignmentTest
		tempMap = new HashMap<>();
		tempMap.put("0x1f1e1d",
			"50 61 72 73 65 72 54 6f 6b 65 6e 54 79 70 65 73 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
				"00 00 50 61 72 73 65 72 54 6f 6b 65 6e 54 79 70 65 73 00 00");
		programBytesMap.put("alignmentTest", tempMap);

		MemBlockParams[] alignmentTextMemBlocks = new MemBlockParams[1];
		alignmentTextMemBlocks[0] = new MemBlockParams("0x1f1e10", 62, true, false, false);
		programMemBlocksMap.put("alignmentTest", alignmentTextMemBlocks);

		// Bytes for stringOverInstructionTest
		tempMap = new HashMap<>();
		tempMap.put("0x10000",
			"01 00 22 30 00 2d 25 73 20 25 73 20 25 73 20 25 73 00 00 00 00 00 " +
				"2d 25 73 20 25 73 20 25 73 20 25 73 00 00");
		programBytesMap.put("stringOverInstructionTest", tempMap);

		MemBlockParams[] stringOverInstructionMemBlocks = new MemBlockParams[1];
		stringOverInstructionMemBlocks[0] = new MemBlockParams("0x10000", 100);
		programMemBlocksMap.put("stringOverInstructionTest", stringOverInstructionMemBlocks);

		// Bytes for stringOverUndefinedTest
		tempMap = new HashMap<>();
		tempMap.put("0x11000", "6e 6f 74 65 70 61 64 00"); // notepad
		programBytesMap.put("stringOverUndefinedTest", tempMap);

		MemBlockParams[] stringOverUndefinedMemBlocks = new MemBlockParams[1];
		stringOverUndefinedMemBlocks[0] = new MemBlockParams("0x11000", 100);
		programMemBlocksMap.put("stringOverUndefinedTest", stringOverUndefinedMemBlocks);

	}

	@After
	public void tearDown() throws Exception {

		System.gc();
	}

	private Program buildProgram(String programName, boolean disassemble) throws Exception {

		Program testProgram;

		if (!programBytesMap.containsKey(programName)) {
			Assert.fail("Don't have any information to create: " + programName);
		}

		builder = new ProgramBuilder(programName, ProgramBuilder._TOY);

		MemBlockParams[] memBlocks = programMemBlocksMap.get(programName);

		for (int i = 0; i < memBlocks.length; i++) {
			MemoryBlock currMemBlock = builder.createMemory("strings" + i,
				memBlocks[i].getStartAddress(), memBlocks[i].getBlockSize());

			builder.setRead(currMemBlock, memBlocks[i].getRead());
			builder.setWrite(currMemBlock, memBlocks[i].getWrite());
			builder.setExecute(currMemBlock, memBlocks[i].getExecute());
		}

		HashMap<String, String> bytes = (HashMap<String, String>) programBytesMap.get(programName);
		for (String startAddr : bytes.keySet()) {
			builder.setBytes(startAddr, bytes.get(startAddr), disassemble);
		}

		testProgram = builder.getProgram();
		testProgram.startTransaction("TEST_" + programName);

		return testProgram;
	}

	/**
	 * Check that some simple strings that we expect to find are found, at the correct addresses.
	 * @throws Exception
	 */
	@Test
	public void testFindValidStrings() throws Exception {

		Program testProgram = buildProgram("notepad.exe", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		// These are the strings that we expect to find, with their corresponding offsets
		String[] strings =
			new String[] { "Notepad", "Now Printing", "Paper", "NpSaveDialog", "Preview" };
		int[] offsets = new int[] { 0x1008018, 0x100d612, 0x100d72e, 0x10013b0, 0x100daaa };

		HashMap<Address, String> addressToValueMap = new HashMap<>();

		// Translate offsets to addresses
		for (int i = 0; i < offsets.length; i++) {
			addressToValueMap.put(addr(space, offsets[i]), strings[i]);
		}

		Data data;

		// Verify these strings aren't already there
		for (Address strAddr : addressToValueMap.keySet()) {
			data = listing.getDefinedDataAt(strAddr);
			assertNull(data);
		}

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setStringEndAlignment(1);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		String type, actualValue, toMatch;

		// Verify that each expected string is there
		for (Address strAddr : addressToValueMap.keySet()) {
			toMatch = "u\"" + addressToValueMap.get(strAddr) + "\"";

			data = listing.getDefinedDataAt(strAddr);
			assertNotNull(data);

			type = data.getDataType().getName().toLowerCase();
			assertTrue("Data at address " + strAddr + " should be a type of string!",
				(type.contains("unicode") || type.contains("string")));

			actualValue = data.getDefaultValueRepresentation();
			assertEquals(toMatch, actualValue);
		}
	}

	/**
	 * Verifies normal operation of the Strings Analyzer -- that these specific strings
	 * are created by the Analyzer when default options are checked!
	 */
	@Test
	public void testDefaultStringsCreation() throws Exception {

		Program testProgram = buildProgram("libopencoreplayer.so", false);

		Data dataHere;
		String stringHere;

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		String[] existingStrings = new String[] { "drm/duration", "PVFMVideoMIO",
			"set to invalid mode (%d)", "device", "height", "PLAYER_QUIT", "video/decoder" };

		int[] offsets = new int[] { 0xa7198120, 0xa7195fd4, 0xa7196ee8, 0xa717fa48, 0xa71956a0,
			0xa7197304, 0xa718025c };
		Address[] existingAddresses = new Address[offsets.length];

		for (int i = 0; i < offsets.length; i++) {
			existingAddresses[i] = addr(space, offsets[i]);
		}

		// Verify strings aren't already there
		for (Address existingAddresse : existingAddresses) {
			dataHere = listing.getDefinedDataAt(existingAddresse);
			assertNull(dataHere);
		}

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		// Run strings analyzer that shouldn't make the bigger string around this one
		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setCreateStringOverExistingString(false);
		analyzer.setStringEndAlignment(1);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		for (int i = 0; i < existingStrings.length; i++) {
			// Verify string is actually there
			dataHere = listing.getDefinedDataAt(existingAddresses[i]);
			assertNotNull(dataHere);
			stringHere = dataHere.getDefaultValueRepresentation();

			assertEquals("\"" + existingStrings[i] + "\"", stringHere);
		}
	}

	/**
	 * Test that these specific strings are _not_ created when default options are checked.
	 * @throws Exception
	 */
	@Test
	public void testDefaultStringsNotCreated() throws Exception {

		Program testProgram = buildProgram("msvidctl.dll", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		// Locations of strings created in "testNullTermination"
		int[] nonExpectedOffsets = new int[] { 0x5a2afc20, 0x5a2b00e4, 0x5a2b0384, 0x5a2cdafe,
			0x5a2cdcd2, 0x5a2b5278, 0x5a2b598e };

		Data dataHere;

		// Verify these strings aren't already there (before running the Strings Analyzer)
		for (int nonExpectedOffset : nonExpectedOffsets) {
			dataHere = listing.getDefinedDataAt(addr(space, nonExpectedOffset));
			assertNull(dataHere);
		}

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		// Run strings analyzer that shouldn't make the bigger string around this one
		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setCreateStringOverExistingString(false);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		for (int nonExpectedOffset : nonExpectedOffsets) {
			dataHere = listing.getDefinedDataAt(addr(space, nonExpectedOffset));
			assertNull(dataHere);
		}
	}

	/**
	 *  Verify that unchecking then checking the "Create strings containing existing strings"
	 *  option works as expected.
	 */
	@Test
	public void testStringsContainingExistingStrings() throws Exception {

		Program testProgram = buildProgram("libopencoreplayer.so", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		// Create a string that overlaps where a string normally would be automatically created.
		String[] makeExistingStrs = new String[] { "duration", "VideoMIO" };
		int[] offsets = new int[] { 0xa7198124, 0xa7195fd8 };
		Address[] makeExistingAddrs = new Address[offsets.length];

		CreateDataCmd cmd;
		Data dataHere;
		String stringHere;

		for (int i = 0; i < offsets.length; i++) {
			makeExistingAddrs[i] = addr(space, offsets[i]);
			cmd = new CreateDataCmd(makeExistingAddrs[i], true, new StringDataType());
			cmd.applyTo(testProgram);

			dataHere = listing.getDefinedDataAt(makeExistingAddrs[i]);
			assertNotNull(dataHere);

			stringHere = dataHere.getDefaultValueRepresentation();
			assertEquals("\"" + makeExistingStrs[i] + "\"", stringHere);
		}

		// Offsets where there shouldn't be strings because existing strings were
		// "in the way"
		int[] nonExpectedOffsets = new int[] { 0xa7198120, 0xa7195fd4 };

		// Verify these are not there before running the Strings Analyzer
		for (int nonExpectedOffset : nonExpectedOffsets) {
			dataHere = listing.getDefinedDataAt(addr(space, nonExpectedOffset));
			assertNull(dataHere);
		}

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		// Run strings analyzer
		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setStringEndAlignment(1);
		analyzer.setCreateStringOverExistingString(false);// Option is unchecked
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		for (int nonExpectedOffset : nonExpectedOffsets) {
			dataHere = listing.getDefinedDataAt(addr(space, nonExpectedOffset));
			assertNull(dataHere);
		}

		// Larger string that would have been created if parameter is checked
		String[] largerStrs = new String[] { "drm/duration", "PVFMVideoMIO" };

		// Now run again with parameter enabled and verify strings are there
		analyzer.setCreateStringOverExistingString(true);// Option is checked
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		for (int i = 0; i < nonExpectedOffsets.length; i++) {
			dataHere = listing.getDefinedDataAt(addr(space, nonExpectedOffsets[i]));
			assertNotNull(dataHere);
			stringHere = dataHere.getDefaultValueRepresentation();
			assertEquals("\"" + largerStrs[i] + "\"", stringHere);
		}
	}

	/**
	 *  Verify that unchecking then checking the "Create strings containing references"
	 *  option works as expected.
	 */
	@Test
	public void testStringsContainingRefs() throws Exception {

		Program testProgram = buildProgram("libopencoreplayer.so", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		// Offsets where there shouldn't be strings because existing refs were "in the way"
		int[] nonExpectedOffsets = new int[] { 0xa7195fd4, 0xa7196ee8 };
		Data dataHere;

		// Verify these aren't here before running Strings Analyzer
		for (int nonExpectedOffset : nonExpectedOffsets) {
			dataHere = listing.getDefinedDataAt(addr(space, nonExpectedOffset));
			assertNull(dataHere);
		}

		// Create references
		ReferenceManager refMgr = testProgram.getReferenceManager();
		refMgr.addMemoryReference(addr(space, 0xa7197898), addr(space, 0xa7195fda), RefType.DATA,
			SourceType.USER_DEFINED, 1);

		refMgr.addMemoryReference(addr(space, 0xa7196f62), addr(space, 0xa7196efc), RefType.DATA,
			SourceType.USER_DEFINED, 1);

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		// Run strings analyzer
		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setCreateStringOverExistingReference(false);// Option is unchecked
		analyzer.setStringEndAlignment(1);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		for (int nonExpectedOffset : nonExpectedOffsets) {
			dataHere = listing.getDefinedDataAt(addr(space, nonExpectedOffset));
			assertNull(dataHere);
		}

		// String that would have been created if parameter is checked
		String[] largerStrs = new String[] { "PVFMVideoMIO", "set to invalid mode (%d)" };
		String[] nullBits = new String[] { "00", "00" };

		// Now run again with parameter enabled and verify strings are there
		analyzer.setCreateStringOverExistingReference(true);// Option is checked
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		String stringHere;
		for (int i = 0; i < nonExpectedOffsets.length; i++) {
			dataHere = listing.getDefinedDataAt(addr(space, nonExpectedOffsets[i]));
			assertNotNull(dataHere);
			stringHere = dataHere.getDefaultValueRepresentation();
			assertEquals("\"" + largerStrs[i] + "\"", stringHere);
		}
	}

	/**
	 * Test that the minimum string length parameter works -- strings shorter than the minimum
	 * string length should not be created.
	 */
	@Test
	public void testMinStringLength() throws Exception {

		Program testProgram = buildProgram("libopencoreplayer.so", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		// Test strings
		String[] existingStrings = new String[] { "drm/duration", "PVFMVideoMIO",
			"set to invalid mode (%d)", "device", "height", "PLAYER_QUIT", "video/decoder" };
		int[] offsets = new int[] { 0xa7198120, 0xa7195fd4, 0xa7196ee8, 0xa717fa48, 0xa71956a0,
			0xa7197304, 0xa718025c };

		// Sort strings by length
		TreeMap<Integer, List<String>> stringsBySize = new TreeMap<>();
		HashMap<String, Address> stringToAddr = new HashMap<>();

		int strLen;

		for (int i = 0; i < existingStrings.length; i++) {
			stringToAddr.put(existingStrings[i], addr(space, offsets[i]));

			strLen = existingStrings[i].length();

			if (!stringsBySize.containsKey(strLen)) {
				List<String> tempArr = new ArrayList<>();
				tempArr.add(existingStrings[i]);
				stringsBySize.put(strLen, tempArr);
			}
			else {
				stringsBySize.get(strLen).add(existingStrings[i]);
			}
		}

		Data dataHere;

		// Verify none of these strings exist prior to running the Strings Analyzer
		for (String candidateStr : stringToAddr.keySet()) {
			dataHere = listing.getDefinedDataAt(stringToAddr.get(candidateStr));
			assertNull(dataHere);
		}

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		// Run strings analyzer for each string length
		StringsAnalyzer analyzer = new StringsAnalyzer();

		List<Integer> strSizes = new ArrayList<>(stringsBySize.keySet());
		String stringHere;

		// First verify that setting min string size to one greater than largest string
		// will result in none of the test strings being made
		analyzer.setMinStringLength(strSizes.get(strSizes.size() - 1) + 1);
		analyzer.setStringEndAlignment(1);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		for (String candidateStr : stringToAddr.keySet()) {
			dataHere = listing.getDefinedDataAt(stringToAddr.get(candidateStr));
			assertNull("Did not expect to find '" + candidateStr +
				"' when min string length is set to " + strSizes.get(strSizes.size() - 1) + 1,
				dataHere);
		}

		// Now decrease min string size to equivalent to each of test string sizes, run analyzer,
		// and verify that expected strings are/aren't created
		for (int j = strSizes.size() - 1; j >= 0; j--) {
			int minStrLen = strSizes.get(j);

			// Run analyzer with min string size equal to size of current set of strings
			analyzer.setMinStringLength(strSizes.get(j));
			analyzer.added(testProgram, null, monitor, manager.getMessageLog());

			// Verify that strings below this size do not exist
			for (int k = 0; k < j; k++) {
				for (String thisString : stringsBySize.get(strSizes.get(k))) {
					dataHere = listing.getDefinedDataAt(stringToAddr.get(thisString));
					assertNull("Did not expect to find: '" + thisString +
						"' when min str length is set to " + minStrLen, dataHere);
				}
			}

			// Verify that strings this size and higher do exist
			for (int k = j; k < strSizes.size(); k++) {
				for (String thisString : stringsBySize.get(strSizes.get(k))) {
					// Verify string is actually there
					dataHere = listing.getDefinedDataAt(stringToAddr.get(thisString));
					assertNotNull("Expected to find: '" + thisString +
						"' when min string length is set to " + minStrLen, dataHere);
					stringHere = dataHere.getDefaultValueRepresentation();

					assertEquals("\"" + thisString + "\"", stringHere);
				}
			}
		}
	}

	/**
	 * Test that unchecking the "Require null termination for string" parameter works -- strings
	 * that are valid strings, but don't end in null bytes should be created.
	 */
	@Test
	public void testNullTermination() throws Exception {

		Program testProgram = buildProgram("msvidctl.dll", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		String[] existingStrings = new String[] { "KeyPress", "FriendlyName", "RemoteWriteW",
			"Longitude in tenths of a degreeWWW",
			"Returns an enumerator for Tuning Spaces accepted by this tuner" };
		int[] offsets = new int[] { 0x5a2afc20, 0x5a2b00e4, 0x5a2b0384, 0x5a2cdafe, 0x5a2cdcd2 };
		Address[] existingAddresses = new Address[offsets.length];

		for (int i = 0; i < offsets.length; i++) {
			existingAddresses[i] = addr(space, offsets[i]);
		}

		Data dataHere;

		// Verify none of these strings are here before running Strings Analyzer
		for (Address currAddress : existingAddresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		// Verify that these strings are not created when the options is checked
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setRequireNullTermination(true);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		for (Address currAddress : existingAddresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		analyzer.setRequireNullTermination(false);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		String stringHere;

		for (int i = 0; i < existingStrings.length; i++) {
			// Verify string is actually there
			dataHere = listing.getDefinedDataAt(existingAddresses[i]);
			assertNotNull(dataHere);
			stringHere = dataHere.getDefaultValueRepresentation();

			assertEquals("\"" + existingStrings[i] + "\"", stringHere);
		}
	}

	/**
	 * Test that adjusting the string alignment value to "2" works. The strings tested here
	 * should be created when the alignment is set to 2, but not at alignment 4.
	 *
	 * @throws Exception
	 */
	@Test
	public void testStringStartAlignAt2() throws Exception {

		Program testProgram = buildProgram("msvidctl.dll", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		String[] existingStrings = new String[] { "WDIMSVidOutputDeviceWW(#", "DLVideoWWWP-" };
		int[] offsets = new int[] { 0x5a2b4aea, 0x5a2b598e };
		Address[] existingAddresses = new Address[offsets.length];

		for (int i = 0; i < offsets.length; i++) {
			existingAddresses[i] = addr(space, offsets[i]);
		}

		Data dataHere;

		// Verify these strings do not exist prior to running the Strings Analyzer
		for (Address currAddress : existingAddresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);
		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setStringEndAlignment(1);

		// Verify these strings are not created when alignment is set to 4
		analyzer.setStringStartAlignment(4);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		for (Address currAddress : existingAddresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		analyzer.setStringStartAlignment(2);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		String stringHere;

		for (int i = 0; i < existingStrings.length; i++) {
			// Verify string is actually there
			dataHere = listing.getDefinedDataAt(existingAddresses[i]);
			assertNotNull(dataHere);
			stringHere = dataHere.getDefaultValueRepresentation();

			assertEquals("\"" + existingStrings[i] + "\"", stringHere);
		}

	}

	/**
	 * Test that adjusting the string alignment value to "4" works. The strings tested here
	 * should be created when the alignment is set to 4.
	 *
	 * Also test that strings that would be created at Align_2 (but not at Align_4) are not created.
	 *
	 * @throws Exception
	 */
	@Test
	public void testStringStartAlignAt4() throws Exception {

		Program testProgram = buildProgram("msvidctl.dll", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		String[] existingStrings = new String[] { "ReleaseBoundObjectsW`\\t", "currentImage(#",
			"ContentBecomingStale,3", "EnumMediaTypesWW0*" };
		int[] offsets = new int[] { 0x5a2b07a8, 0x5a2b5278, 0x5a2b6270, 0x5a2cc2fc };

		String[] stringsAlignedAt2 = new String[] { "mciSendCommandW", "Component Type,",
			"Set the sink filter (CLSID)WWW\\t", "MS Video Control Interface;" };
		int[] offsetsAlignedAt2 = new int[] { 0x5a29b0c2, 0x5a2b7722, 0x5a2b891a, 0x5a2b90b2 };

		Address[] existingAddresses = new Address[offsets.length];
		Address[] alignAt2Addresses = new Address[offsetsAlignedAt2.length];

		for (int i = 0; i < offsets.length; i++) {
			existingAddresses[i] = addr(space, offsets[i]);
		}

		for (int i = 0; i < alignAt2Addresses.length; i++) {
			alignAt2Addresses[i] = addr(space, offsetsAlignedAt2[i]);
		}

		Data dataHere;

		// Verify these strings do not exist prior to running the Strings Analyzer
		for (Address currAddress : existingAddresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		for (Address currAddress : alignAt2Addresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setStringStartAlignment(4);
		analyzer.setStringEndAlignment(1);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		String stringHere;

		for (int i = 0; i < existingStrings.length; i++) {
			// Verify string is actually there
			dataHere = listing.getDefinedDataAt(existingAddresses[i]);
			assertNotNull(dataHere);
			stringHere = dataHere.getDefaultValueRepresentation();

			assertEquals("\"" + existingStrings[i] + "\"", stringHere);
		}

		// Verify "aligned at 2" strings still not there
		for (Address currAddress : alignAt2Addresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		// Verify the Align_2 strings are created when start alignment is changed to 2
		analyzer.setStringStartAlignment(2);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		for (int i = 0; i < stringsAlignedAt2.length; i++) {
			// Verify string is actually there
			dataHere = listing.getDefinedDataAt(alignAt2Addresses[i]);
			assertNotNull(dataHere);
			stringHere = dataHere.getDefaultValueRepresentation();

			assertEquals("\"" + stringsAlignedAt2[i] + "\"", stringHere);
		}

	}

	/**
	 * Test that an end string alignment value of "4" (default value) works. Setting the end string
	 * alignment looks for 00's to pad the string so that whatever follows this string is aligned
	 * to the selected alignment. This should only work if the "require null termination" option
	 * is enabled.
	 *
	 * @throws Exception
	 */
	@Test
	public void testStringEndAlignAt4() throws Exception {

		Program testProgram = buildProgram("finder.exe", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		String[] existingStrings = new String[] { "TLOSS error\\r\\n", "SING error\\r\\n",
			"Microsoft Visual C++ Runtime Library", "GetLastActivePopup" };
		int[] offsets = new int[] { 0x300010d0, 0x300010e0, 0x30001348, 0x300013ac };
		int[] extraLength = new int[] { 2, 3, 3, 1 };

		Address[] existingAddresses = new Address[offsets.length];

		for (int i = 0; i < offsets.length; i++) {
			existingAddresses[i] = addr(space, offsets[i]);
		}

		Data dataHere;

		// Verify these strings do not exist prior to running the Strings Analyzer
		for (Address currAddress : existingAddresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setStringEndAlignment(4);
		analyzer.setRequireNullTermination(true);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		String stringHere;

		for (int i = 0; i < existingStrings.length; i++) {
			// Verify string is actually there
			dataHere = listing.getDefinedDataAt(existingAddresses[i]);
			assertNotNull(dataHere);
			stringHere = dataHere.getDefaultValueRepresentation();

			// String will look something like --> "My String",00
			StringBuilder buildMyString = new StringBuilder("\"" + existingStrings[i] + "\"");

			assertEquals(buildMyString.toString(), stringHere);
		}
	}

	/**
	 * Test that an end string alignment value of "4" (default value) works. Setting the end string
	 * alignment looks for 00's to pad the string so that whatever follows this string is aligned
	 * to the selected alignment. This should only work if the "require null termination" option
	 * is enabled.
	 *
	 * @throws Exception
	 */
	@Test
	public void testStringEndAlignAt7() throws Exception {

		Program testProgram = buildProgram("finder.exe", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		String[] existingStrings = new String[] { "SING error\\r\\n",
			"Microsoft Visual C++ Runtime Library", "GetLastActivePopup", "user32.dll" };
		int[] offsets = new int[] { 0x300010e0, 0x30001348, 0x300013ac, 0x300013dc };
		int[] extraLength = new int[] { 1, 0, 0, 2 };

		Address[] existingAddresses = new Address[offsets.length];

		for (int i = 0; i < offsets.length; i++) {
			existingAddresses[i] = addr(space, offsets[i]);
		}

		Data dataHere;

		// Verify these strings do not exist prior to running the Strings Analyzer
		for (Address currAddress : existingAddresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setStringEndAlignment(7);
		analyzer.setRequireNullTermination(true);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		String stringHere;

		for (int i = 0; i < existingStrings.length; i++) {
			// Verify string is actually there
			dataHere = listing.getDefinedDataAt(existingAddresses[i]);
			assertNotNull(dataHere);
			stringHere = dataHere.getDefaultValueRepresentation();

			// String will look something like --> "My String",00
			StringBuilder buildMyString = new StringBuilder("\"" + existingStrings[i] + "\"");

			assertEquals(buildMyString.toString(), stringHere);
		}
	}

	/**
	 * Test that the "end alignment" parameter has no effect when the "Require null termination
	 * for string" option is unchecked. That is, created strings either have ONE null terminator
	 * or none (there are no extra padding bytes added to the end).
	 *
	 * @throws Exception
	 */
	@Test
	public void testEndAlignWithNoNullTermination() throws Exception {

		Program testProgram = buildProgram("finder.exe", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		String[] existingStrings = new String[] { "TLOSS error\\r\\n", "SING error\\r\\n",
			"Microsoft Visual C++ Runtime Library", "GetLastActivePopup" };
		int[] offsets = new int[] { 0x300010d0, 0x300010e0, 0x30001348, 0x300013ac };

		Address[] existingAddresses = new Address[offsets.length];

		for (int i = 0; i < offsets.length; i++) {
			existingAddresses[i] = addr(space, offsets[i]);
		}

		Data dataHere;

		// Verify these strings do not exist prior to running the Strings Analyzer
		for (Address currAddress : existingAddresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setStringEndAlignment(4);
		analyzer.setRequireNullTermination(false);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		String stringHere;

		for (int i = 0; i < existingStrings.length; i++) {
			// Verify string is actually there
			dataHere = listing.getDefinedDataAt(existingAddresses[i]);
			assertNotNull(dataHere);
			stringHere = dataHere.getDefaultValueRepresentation();

			// String will look something like --> "My String",00
			String buildMyString = "\"" + existingStrings[i] + "\"";
			assertEquals(buildMyString, stringHere);
		}
	}

	/**
	 * Test that enabling "Search only in accessible memory blocks" only looks for strings
	 * in memory blocks that have one or more of the R, W, or X permissions set.
	 *
	 * Test that disabling the option allows strings to be made in all memory blocks regardless
	 * of permissions.
	 *
	 * @throws Exception
	 */
	@Test
	public void testCreateStringsInAccessibleMemoryBlocksOnly() throws Exception {

		Program testProgram = buildProgram("xtraceroute", false);

		Listing listing = testProgram.getListing();

		// These inaccessible strings will be in the .comment address space/memory block
		String[] inaccessibleStrings =
			new String[] { "GCC: (GNU) 3.2 20020720 (Red Hat Linux Rawhide 3.2-0.1)",
				"GCC: (GNU) 3.2 20020720 (Red Hat Linux Rawhide 3.2-0.1.1)" };
		int[] offsets = new int[] { 0x00000001, 0x000002fc };

		String[] accessibleStrings =
			new String[] { "Anguilla", "Q80@AT", "Bosnia and Herzegowina", "Kingdom of Sweden" };
		int[] offsets2 = new int[] { 0x08057b60, 0x08057e38, 0x08057fb0, 0x0805bc6c };
		boolean[] shouldExist = new boolean[] { true, false, true, true };

		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		Address[] inaccessibleAddresses = new Address[offsets.length];
		Address[] accessibleAddresses = new Address[offsets2.length];

		for (int i = 0; i < offsets.length; i++) {
			inaccessibleAddresses[i] = addr(space, offsets[i]);
		}

		for (int i = 0; i < offsets2.length; i++) {
			accessibleAddresses[i] = addr(space, offsets2[i]);
		}

		Data dataHere;

		// Verify none of the strings exist prior to running the Strings Analyzer
		for (Address currAddress : inaccessibleAddresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		for (Address currAddress : accessibleAddresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		// Set to search only accessible memory blocks. We don't expect to find the
		// 'inaccessible' strings in this case.
		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setSearchAccessibleMemoryBlocks(true);
		analyzer.setStringEndAlignment(1);
		analyzer.setRequireNullTermination(false);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		// Verify the inaccessible strings still don't exist
		for (Address currAddress : inaccessibleAddresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		// But most of the accessible strings should exist
		String stringHere;

		for (int i = 0; i < accessibleAddresses.length; i++) {
			dataHere = listing.getDefinedDataAt(accessibleAddresses[i]);

			if (shouldExist[i]) {
				assertNotNull(dataHere);
				stringHere = dataHere.getDefaultValueRepresentation();

				// String will look something like --> "My String",00
				String buildMyString = "\"" + accessibleStrings[i] + "\"";
				assertEquals(buildMyString, stringHere);
			}
			else {
				assertNull(dataHere);
			}
		}

		// Set to search all memory blocks
		analyzer.setSearchAccessibleMemoryBlocks(false);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		for (int i = 0; i < inaccessibleStrings.length; i++) {
			// Verify formerly inaccessible strings are now there
			dataHere = listing.getDefinedDataAt(inaccessibleAddresses[i]);
			assertNotNull(dataHere);
			stringHere = dataHere.getDefaultValueRepresentation();

			// String will look something like --> "My String",00
			String buildMyString = "\"" + inaccessibleStrings[i] + "\"";
			assertEquals(buildMyString, stringHere);
		}
	}

	/**
	 * Test that checking the "force reload" box and assigning a new model file results in
	 * a new model being loaded and different strings being found.
	 *
	 * @throws Exception
	 */
	@Test
	public void testForceReloadModels() throws Exception {

		Program testProgram = buildProgram("libopencoreplayer.so", false);

		// Strings that will only be found in the "good" (regular) model
		String[] stringsInGoodModel = new String[] { "device", "video/decoder", "player" };
		int[] goodStringOffsets = new int[] { 0xa717fa48, 0xa718025c, 0xa71802a8 };
		Address[] goodStringAddresses = new Address[goodStringOffsets.length];

		// Strings that will only be found in the "bad" (contrived) model
		String[] stringsInBadModel = new String[] { "tnihtxetL\\t", "OMXAacDec", "rBBASepzNnLr" };
		int[] badStringOffsets = new int[] { 0xa71756c4, 0xa7192c00, 0xa7192fa0 };
		Address[] badStringAddresses = new Address[badStringOffsets.length];

		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		for (int i = 0; i < goodStringOffsets.length; i++) {
			goodStringAddresses[i] = addr(space, goodStringOffsets[i]);
		}

		for (int i = 0; i < badStringOffsets.length; i++) {
			badStringAddresses[i] = addr(space, badStringOffsets[i]);
		}

		// Run as usual, verify that "good model" strings exist, but not "bad model" strings.
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setStringEndAlignment(1);

		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		// Verify these strings don't exist
		Data dataHere;
		Listing listing = testProgram.getListing();

		for (Address currAddress : badStringAddresses) {
			dataHere = listing.getDefinedDataAt(currAddress);
			assertNull(dataHere);
		}

		// Verify these strings exist
		String stringHere;
		for (int i = 0; i < stringsInGoodModel.length; i++) {
			// Verify string is actually there
			dataHere = listing.getDefinedDataAt(goodStringAddresses[i]);
			assertNotNull(dataHere);
			stringHere = dataHere.getDefaultValueRepresentation();

			// String will look something like --> "My String",00
			String buildMyString = "\"" + stringsInGoodModel[i] + "\"";
			assertEquals(buildMyString, stringHere);
		}

		// Create and load the "bad" model -- needs to be in the same directory as current model
		List<ResourceFile> modelFiles = Application.findFilesByExtensionInApplication(".sng");

		if (modelFiles.size() == 0) {
			Assert.fail("Could not find directory containing the .sng string n-grams model!");
		}

		// Use the first result for reference (there should only be one result)
		ResourceFile containingFolder = modelFiles.get(0).getParentFile();
		File tempFile = new File(containingFolder.getFile(true), "tempStringNGrams.sng");

		tempFile.delete();

		try {
			boolean createSuccess = tempFile.createNewFile();
			assertTrue("File '" + tempFile.getAbsolutePath() + "' should have been created!",
				createSuccess);

			FileWriter output = new FileWriter(tempFile);
			BufferedWriter writer = new BufferedWriter(output);
			writer.write("# Model Type: lowercase\n\n");

			// Basic model where all trigrams made up of the letters a - z have the same probability
			for (int first = 'a'; first <= 'z'; first++) {
				for (int second = 'a'; second <= 'z'; second++) {
					for (int third = 'a'; third <= 'z'; third++) {
						writer.write(
							(char) first + "\t" + (char) second + "\t" + (char) third + "\t500\n");
					}
				}
			}

			writer.close();

			// Leave off extension; the file should still be found correctly
			analyzer.setModelName("tempStringNGrams");
			analyzer.setForceModelReload(true);

			analyzer.added(testProgram, null, monitor, manager.getMessageLog());

			// Verify the "bad" strings now exist
			for (int i = 0; i < stringsInBadModel.length; i++) {
				// Verify string is actually there
				dataHere = listing.getDefinedDataAt(badStringAddresses[i]);
				assertNotNull("Expecting " + stringsInBadModel[i] + " at " + badStringOffsets[i],
					dataHere);
				stringHere = dataHere.getDefaultValueRepresentation();

				// String will look something like --> "My String",00
				String buildMyString = "\"" + stringsInBadModel[i] + "\"";
				assertEquals(buildMyString, stringHere);
			}

		}
		finally {
			tempFile.delete();
		}
	}

	/**
	 * Check that a string that should be padded up to a 4-byte boundary is padded in normal
	 * circumstances (i.e., when there is room for the padding), but not when the padding
	 * crosses over memory boundaries.
	 *
	 * @throws Exception
	 */
	@Test
	public void testPadStringsOnBoundaries() throws Exception {

		Program testProgram = buildProgram("alignmentTest", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		// These are the strings that we expect to find, with their corresponding offsets
		String[] strings = new String[] { "ParserTokenTypes", "ParserTokenTypes" };
		int[] offsets = new int[] { 0x1f1e1d, 0x1f1e3c };

		HashMap<Address, String> addressToValueMap = new HashMap<>();

		// Translate offsets to addresses
		for (int i = 0; i < offsets.length; i++) {
			addressToValueMap.put(addr(space, offsets[i]), strings[i] + "\"");
		}

		Data data;

		// Verify these strings aren't already there
		for (Address strAddr : addressToValueMap.keySet()) {
			data = listing.getDefinedDataAt(strAddr);
			assertNull(data);
		}

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.setStringEndAlignment(4);
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		String type, actualValue, toMatch;

		// Verify that each expected string is there and padded to expected pad length
		for (Address strAddr : addressToValueMap.keySet()) {
			toMatch = "\"" + addressToValueMap.get(strAddr);

			data = listing.getDefinedDataAt(strAddr);
			assertNotNull(data);

			type = data.getDataType().getName().toLowerCase();
			assertTrue("Data at address " + strAddr + " should be a type of string!",
				(type.contains("unicode") || type.contains("string")));

			actualValue = data.getDefaultValueRepresentation();
			assertEquals(toMatch, actualValue);
		}
	}

	/**
	 * Check that a string that intersects with an instruction (string's start address is the end
	 * address of an instruction) is not created. The same string without instruction overlap
	 * will be created.
	 *
	 * @throws Exception
	 */
	@Test
	public void testCreateStringOverInstruction() throws Exception {

		Program testProgram = buildProgram("stringOverInstructionTest", true);
		builder.clearCodeUnits("0x10006", "0x10032", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();

		String expectedString = "\"-%s %s %s %s\"";
		Address createdAddr = addr(space, 0x10016);
		Address notCreatedAddr = addr(space, 0x10004);

		Data data;

		// Verify these strings aren't already there
		data = listing.getDefinedDataAt(createdAddr);
		assertNull(data);

		data = listing.getDefinedDataAt(notCreatedAddr);
		assertNull(data);

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);

		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		String type, actualValue;

		// Verify that expected string is there
		data = listing.getDefinedDataAt(createdAddr);
		assertNotNull(data);

		type = data.getDataType().getName().toLowerCase();
		assertTrue("Data at address " + createdAddr + " should be a type of string!",
			(type.contains("unicode") || type.contains("string")));

		actualValue = data.getDefaultValueRepresentation();
		assertEquals(expectedString, actualValue);

		// Verify that each non-expected string is not there
		data = listing.getDefinedDataAt(notCreatedAddr);
		assertNull(data);
	}

	@Test
	public void testCreateStringOverUndefined() throws Exception {

		Program testProgram = buildProgram("stringOverUndefinedTest", false);

		Listing listing = testProgram.getListing();
		AddressSpace space = testProgram.getLanguage().getAddressFactory().getDefaultAddressSpace();
		Address addr = addr(space, 0x11000);

		// Create undefined data type at start and middle of string
		listing.createData(addr, Undefined.getUndefinedDataType(1));
		listing.createData(addr.add(3), Undefined.getUndefinedDataType(1));
		Data data = listing.getDefinedDataAt(addr);
		assertNotNull(data);

		// Run StringAnalyzer
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(testProgram);
		StringsAnalyzer analyzer = new StringsAnalyzer();
		analyzer.added(testProgram, null, monitor, manager.getMessageLog());

		// Make sure our string got created, despite the undefined being there
		data = listing.getDefinedDataAt(addr);
		assertNotNull(data);
		String type = data.getDataType().getName().toLowerCase();
		assertTrue("Data at address " + addr + " should be a type of string instead of " + type,
			type.contains("string"));
	}

	private Address addr(AddressSpace space, long offset) {
		return space.getAddress(offset);
	}
}
