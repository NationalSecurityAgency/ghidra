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

package ghidra.app.plugin.core.disassembler;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class AddressTableAnalyzerTest extends AbstractGenericTest {

	private ProgramDB program;
	private ProgramBuilder builder;
	private int pointerSize;
	private String[] targets;

	@Before
	public void setUp() throws Exception {
		targets = new String[] { "0x101000", "0x101100", "0x101200", "0x101300" };
		builder = new ProgramBuilder("AddressTableAnalyzerTest", ProgramBuilder._X64);
		builder.createMemory(".text", "0x100000", 0x1000);
		builder.createMemory(".data", "0x101000", 0x1000);
		program = builder.getProgram();
		pointerSize = program.getDefaultPointerSize();
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	@Test
	public void testAnalyzerCreatesTableOverUndefinedData() throws Exception {
		assertAnalyzerCreatesTableOver(undefinedDataType());
	}

	@Test
	public void testAnalyzerCreatesTableOverUndefinedArray() throws Exception {
		assertAnalyzerCreatesTableOver(undefinedArrayDataType(targets.length * pointerSize));
	}

	private void assertAnalyzerCreatesTableOver(ArrayDataType dataType) throws Exception {
		Address tableStart = builder.addr("0x101100");

		layOutAddressTable(tableStart);
		defineUndefinedArray(tableStart, dataType.getLength());

		runAnalyzer(tableStart);

		Listing listing = program.getListing();
		for (int i = 0; i < targets.length; i++) {
			Data slot = listing.getDefinedDataAt(tableStart.add(i * pointerSize));
			assertNotNull("missing pointer at table[" + i + "]", slot);
			assertTrue("table[" + i + "] should be a pointer", slot.isPointer());
		}

		Bookmark bookmark = program.getBookmarkManager()
				.getBookmark(tableStart, BookmarkType.ANALYSIS, "Address Table");
		assertNotNull("bookmark should have been created", bookmark);
	}

	private void layOutAddressTable(Address tableStart) throws Exception {
		long base = tableStart.getOffset();
		for (int i = 0; i < targets.length; i++) {
			builder.putAddress(Long.toHexString(base + i * pointerSize), targets[i]);
		}
	}

	private ArrayDataType undefinedDataType() {
		return undefinedArrayDataType(pointerSize);
	}

	private ArrayDataType undefinedArrayDataType(int byteLength) {
		return new ArrayDataType(new Undefined1DataType(), byteLength, 1);
	}

	private void defineUndefinedArray(Address at, int byteLength) {
		builder.withTransaction(() -> {
			new CreateDataCmd(at, undefinedArrayDataType(byteLength))
					.applyTo(program);
		});
	}

	private void runAnalyzer(Address inSet) throws CancelledException {
		int tx = program.startTransaction("analyze");
		try {
			new AddressTableAnalyzer().added(program, new AddressSet(inSet, inSet),
					TaskMonitor.DUMMY, new MessageLog());
		} finally {
			program.endTransaction(tx, true);
		}
	}
}
