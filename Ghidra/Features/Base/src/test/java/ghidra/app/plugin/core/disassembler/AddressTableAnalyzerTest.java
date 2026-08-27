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
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class AddressTableAnalyzerTest extends AbstractGenericTest {

	private static final String BaseUndefinedAddrStr = "0x101100";
	private ProgramDB program;
	private ProgramBuilder builder;
	private int pointerSize;
	private String[] targets;
	private Address[] tableAddrs;
	private AddressTableAnalyzer tableAnalyzer = new AddressTableAnalyzer();

	@Before
	public void setUp() throws Exception {
		targets = new String[] { "0x101000", "0x101100", "0x101200", "0x101300", "0x0", "0x101400", "0x101500", "0x0", "0x101600" };

		builder = new ProgramBuilder("AddressTableAnalyzerTest", ProgramBuilder._X64);
		builder.createMemory(".text", "0x100000", 0x1000);
		builder.createMemory(".data", "0x101000", 0x1000);
		program = builder.getProgram();
		pointerSize = program.getDefaultPointerSize();
		
		tableAddrs = new Address[targets.length];
		for (int i = 0; i < tableAddrs.length; i++) {
			tableAddrs[i] = builder.addr(BaseUndefinedAddrStr).add(i*pointerSize);
		}
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	@Test
	public void testAnalyzerCreatesTableOverDefaultData() throws Exception {
		setMinTableSize(1);
		setupAndAnalyzeTables(Undefined.getUndefinedDataType(1));
		assertBookmarkAt(BaseUndefinedAddrStr);
		assertAnalyzerCreatesTableAt(BaseUndefinedAddrStr,4,true);
		assertBookmarkAt("0x101128");
		assertAnalyzerCreatesTableAt("0x101128",2,true);
		assertBookmarkAt("0x101140");
		assertAnalyzerCreatesTableAt("0x101140",1,false);
	}
	
	@Test
	public void testAnalyzerCreatesTableOverUndefined1Data() throws Exception {
		setMinTableSize(1);
		setupAndAnalyzeTables(Undefined.getUndefinedDataType(1));
		assertBookmarkAt(BaseUndefinedAddrStr);
		assertAnalyzerCreatesTableAt(BaseUndefinedAddrStr,4,true);
		assertBookmarkAt("0x101128");
		assertAnalyzerCreatesTableAt("0x101128",2,true);
		assertBookmarkAt("0x101140");
		assertAnalyzerCreatesTableAt("0x101140",1,false);
	}
	
	@Test
	public void testAnalyzerCreatesTableOverUndefined4Data() throws Exception {
		setMinTableSize(1);
		setupAndAnalyzeTables(Undefined.getUndefinedDataType(4));
		assertBookmarkAt(BaseUndefinedAddrStr);
		assertAnalyzerCreatesTableAt(BaseUndefinedAddrStr,4,true);
		assertBookmarkAt("0x101128");
		assertAnalyzerCreatesTableAt("0x101128",2,true);
		assertBookmarkAt("0x101140");
		assertAnalyzerCreatesTableAt("0x101140",1,false);
	}
	

	@Test
	public void testAnalyzerCreatesTableOverUndefinedPointerArray() throws Exception {
		setMinTableSize(1);
		setupAndAnalyzeTables(Undefined.getUndefinedDataType(pointerSize));
		assertBookmarkAt(BaseUndefinedAddrStr);
		assertAnalyzerCreatesTableAt(BaseUndefinedAddrStr,4,true);
		assertBookmarkAt("0x101128");
		assertAnalyzerCreatesTableAt("0x101128",2,true);
		assertBookmarkAt("0x101140");
		assertAnalyzerCreatesTableAt("0x101140",1,false);
	}
	
	@Test
	public void testAnalyzerCreatesTableMinSize2() throws Exception {
		setMinTableSize(2);
		setupAndAnalyzeTables(Undefined.getUndefinedDataType(1));
		assertBookmarkAt(BaseUndefinedAddrStr);
		assertAnalyzerCreatesTableAt(BaseUndefinedAddrStr,4,true);
		assertNoBookmarkAt("0x101120");
		assertNoDataAt("0x101120");
		assertBookmarkAt("0x101128");
		assertAnalyzerCreatesTableAt("0x101128",2,true);
		assertNoBookmarkAt("0x101140");
		assertNoDataAt("0x101140");
	}
	
	@Test
	public void testAnalyzerCreatesTableWithReference() throws Exception {
		String InternalTableRefAddrStr = "0x101108";
		// reference should split tables
		builder.createMemoryReadReference("0x100000", InternalTableRefAddrStr);
		setupAndAnalyzeTables(Undefined.getUndefinedDataType(1));
		assertBookmarkAt(BaseUndefinedAddrStr);
		assertAnalyzerCreatesTableAt(BaseUndefinedAddrStr,1,false);
		assertAnalyzerCreatesTableAt(InternalTableRefAddrStr,3,true);
		assertBookmarkAt(InternalTableRefAddrStr);
	}
	
	@Test
	public void testAnalyzerCreatesTableWithReferenceMinSize2() throws Exception {
		String InternalTableRefAddrStr = "0x101108";
		// reference should split tables
		builder.createMemoryReadReference("0x100000", InternalTableRefAddrStr);
		setMinTableSize(2);
		setupAndAnalyzeTables(null);
		assertNoBookmarkAt(BaseUndefinedAddrStr);
		assertNoDataAt(BaseUndefinedAddrStr);
		assertAnalyzerCreatesTableAt(InternalTableRefAddrStr,3,true);
		assertBookmarkAt(InternalTableRefAddrStr);
	}

	
	@Test
	public void testAnalyzerCreatesTableOverUndefinedArrayDataMinSize() throws Exception {
		setMinTableSize(2);
		setupAndAnalyzeTables(Undefined.getUndefinedDataType(pointerSize));
		assertAnalyzerCreatesTableAt(BaseUndefinedAddrStr,4,true);
		assertNoBookmarkAt("0x101120");
		assertNoDataAt("0x101120");
		assertBookmarkAt("0x101128");
		assertAnalyzerCreatesTableAt("0x101128",2,true);
		assertNoBookmarkAt("0x101140");
		assertNoDataAt("0x101140");
	}
	
	
	@Test
	public void testAnalyzerCreatesTableWithReferenceOverUndefinedArrayData() throws Exception {
		String InternalTableRefAddrStr = "0x101108";
		// reference should split tables
		builder.createMemoryReadReference("0x100000", InternalTableRefAddrStr);
		setMinTableSize(1);
		setupAndAnalyzeTables(Undefined.getUndefinedDataType(pointerSize));
		assertBookmarkAt(BaseUndefinedAddrStr);
		assertAnalyzerCreatesTableAt(BaseUndefinedAddrStr,1,false);
		assertAnalyzerCreatesTableAt(InternalTableRefAddrStr,3,true);
		assertBookmarkAt(InternalTableRefAddrStr);
	}
	
	private void setupAndAnalyzeTables(DataType elemDataType) throws Exception {
		Address tableStart = builder.addr(BaseUndefinedAddrStr);

		layOutAddressTable(tableStart);
		if (elemDataType != null) {
			defineUndefinedArray(tableStart, elemDataType, (targets.length*pointerSize) / elemDataType.getLength());
		}

		runAnalyzer(tableStart,tableStart.add(targets.length*pointerSize));
	}

	private void assertAnalyzerCreatesTableAt(String tableStartStr, int size, boolean nothingFollows) throws Exception {
		Address tableStart = builder.addr(tableStartStr);

		Listing listing = program.getListing();
		for (int i = 0; i < size; i++) {
			Data slot = listing.getDefinedDataAt(tableStart.add(i * pointerSize));
			assertNotNull("missing pointer at table[" + i + "]", slot);
			assertTrue("table[" + i + "] should be a pointer", slot.isPointer());
		}
		if (nothingFollows) {
			Data slot = listing.getDefinedDataAt(tableStart.add(size * pointerSize));
			assertNull("Should not be a pointer defined", slot);
		}
	}
	

	private void assertNoDataAt(String addrStr) {
		Address addr = builder.addr(addrStr);
		
		Data data = program.getListing().getDefinedDataAt(addr);
		if (data == null) {
			return;
		}
		assertTrue(Undefined.isUndefined(data.getDataType()));
	}
	
	private void assertBookmarkAt(String tableStartStr) {
		Address tableStart = builder.addr(tableStartStr);
		
		Bookmark bookmark = program.getBookmarkManager()
				.getBookmark(tableStart, BookmarkType.ANALYSIS, "Address Table");
		assertNotNull("bookmark should have been created at " + tableStart, bookmark);
	}
	
	private void assertNoBookmarkAt(String tableStartStr) {
		Address tableStart = builder.addr(tableStartStr);
		
		Bookmark bookmark = program.getBookmarkManager()
				.getBookmark(tableStart, BookmarkType.ANALYSIS, "Address Table");
		assertNull("bookmark should NOT have been created at " + tableStart, bookmark);
	}

	private void layOutAddressTable(Address tableStart) throws Exception {
		long base = tableStart.getOffset();
		for (int i = 0; i < targets.length; i++) {
			builder.putAddress(Long.toHexString(base + i * pointerSize), targets[i]);
		}
	}

	private void defineUndefinedArray(Address at, DataType elementType, int numElements) {
		builder.withTransaction(() -> {
			new CreateDataCmd(at, new ArrayDataType(elementType,numElements))
					.applyTo(program);
		});
	}
	
	private void setMinTableSize(int size) {
		builder.tx(() -> {
			int txId = program.startTransaction("Analyze");
			Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
			
			analysisOptions.setInt("Create Address Tables.Minimum Table Size", size);
			
			tableAnalyzer.optionsChanged(analysisOptions.getOptions("Create Address Tables"), program);
			
			program.endTransaction(txId, true); 
		});
	}

	private void runAnalyzer(Address start, Address end) {
		builder.tx(() -> {
			tableAnalyzer.added(program, new AddressSet(start, end),
					TaskMonitor.DUMMY, new MessageLog());
			// need to let full analysis run, as each table found schedules
			// follow on create table analysis so that effects of found table can be processed,
			// then new tables found
			builder.analyze();
		});
	}
}
