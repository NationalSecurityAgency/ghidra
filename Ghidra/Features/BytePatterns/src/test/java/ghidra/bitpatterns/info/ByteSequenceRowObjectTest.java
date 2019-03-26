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
package ghidra.bitpatterns.info;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import org.junit.Before;
import org.junit.Test;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.framework.Application;
import ghidra.util.bytesearch.DittedBitSequence;

public class ByteSequenceRowObjectTest extends AbstractGenericTest {
	private FileBitPatternInfoReader fReader;
	private static final int TOTAL_NUM_FUNCTIONS = 32;

	@Before
	public void setUp() throws IOException {
		ResourceFile resourceFile = Application.getModuleDataSubDirectory("BytePatterns", "test");
		fReader = new FileBitPatternInfoReader(resourceFile.getFile(false));
	}

	@Test
	public void testFirstBytesSize() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		List<ByteSequenceRowObject> firstBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.FIRST, null, null);
		int total = 0;
		for (ByteSequenceRowObject row : firstBytes) {
			total += row.getNumOccurrences();
			double percentage = (100.0 * row.getNumOccurrences()) / TOTAL_NUM_FUNCTIONS;
			assertEquals(percentage, row.getPercentage(), Double.NaN);
		}
		assertEquals(TOTAL_NUM_FUNCTIONS, total);
	}

	@Test
	public void testFirstBytesContextRegisterFiltering() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		List<ByteSequenceRowObject> firstBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.FIRST, null, null);
		ContextRegisterFilter cRegFilter = new ContextRegisterFilter();
		cRegFilter.addRegAndValueToFilter("cReg1", new BigInteger("0"));
		cRegFilter.addRegAndValueToFilter("cReg2", new BigInteger("1"));
		cRegFilter.addRegAndValueToFilter("cReg3", new BigInteger("3"));
		cRegFilter.addRegAndValueToFilter("cReg4", new BigInteger("7"));

		firstBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.FIRST, cRegFilter, null);
		assertEquals(firstBytes.size(), 1);
		ByteSequenceRowObject onlyRow = firstBytes.get(0);
		assertEquals(onlyRow.getNumOccurrences(), 4);
		assertEquals(onlyRow.getPercentage(), 100.0, Double.NaN);
		assertEquals(onlyRow.getDisassembly(),
			" PUSH:1(RBP)  MOV:3(RBP,RSP)  PUSH:1(RBX)  SUB:4(RSP,0x38) ");
	}

	@Test
	public void testFirstBytesLengthFiltering() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		List<ByteSequenceRowObject> firstBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.FIRST, null, null);

		ByteSequenceLengthFilter lFilter = new ByteSequenceLengthFilter(4, 4);
		firstBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.FIRST, null, lFilter);
		assertEquals(firstBytes.size(), 1);

		lFilter = new ByteSequenceLengthFilter(5, 5);
		firstBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.FIRST, null, lFilter);
		assertEquals(firstBytes.size(), 3);

		Map<String, Integer> counts = new HashMap<>();
		for (ByteSequenceRowObject row : firstBytes) {
			counts.put(row.getSequence(), row.getNumOccurrences());
		}

		assertEquals(22, (int) counts.get("554889e548"));
		assertEquals(4, (int) counts.get("554889e553"));
		assertEquals(6, (int) counts.get("554889e589"));
	}

	@Test
	public void testPreBytesSize() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		List<ByteSequenceRowObject> preBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.PRE, null, null);
		int total = 0;

		//the test data has no preBytes for functions with address 0
		for (ByteSequenceRowObject row : preBytes) {
			total += row.getNumOccurrences();
			double percentage = (100.0 * row.getNumOccurrences()) / (TOTAL_NUM_FUNCTIONS - 2);
			assertEquals(percentage, row.getPercentage(), Double.NaN);
		}
		assertEquals(total, (TOTAL_NUM_FUNCTIONS - 2));
	}

	@Test
	public void testPreBytesContextRegisterFiltering() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		List<ByteSequenceRowObject> preBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.PRE, null, null);
		ContextRegisterFilter cRegFilter = new ContextRegisterFilter();
		cRegFilter.addRegAndValueToFilter("cReg1", new BigInteger("0"));
		cRegFilter.addRegAndValueToFilter("cReg2", new BigInteger("1"));
		cRegFilter.addRegAndValueToFilter("cReg3", new BigInteger("3"));
		cRegFilter.addRegAndValueToFilter("cReg4", new BigInteger("7"));

		preBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.PRE, cRegFilter, null);
		assertEquals(preBytes.size(), 1);
		ByteSequenceRowObject onlyRow = preBytes.get(0);
		assertEquals(onlyRow.getNumOccurrences(), 4);
		assertEquals(onlyRow.getPercentage(), 100.0, Double.NaN);
		assertEquals(onlyRow.getDisassembly(), " MOV:3(EAX,[RBP + -0x4])  LEAVE:1()  RET:1() ");

	}

	@Test
	public void testPreBytesLengthFiltering() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		List<ByteSequenceRowObject> preBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.PRE, null, null);
		//test length filtering		
		ByteSequenceLengthFilter lFilter = new ByteSequenceLengthFilter(-2, 2);
		preBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.PRE, null, lFilter);
		assertEquals(preBytes.size(), 1);
		assertEquals(preBytes.get(0).getSequence(), "c9c3");

		lFilter = new ByteSequenceLengthFilter(-3, 3);
		preBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.PRE, null, lFilter);
		assertEquals(preBytes.size(), 7);

		Map<String, Integer> counts = new HashMap<>();
		for (ByteSequenceRowObject row : preBytes) {
			counts.put(row.getSequence(), row.getNumOccurrences());
		}
		assertEquals(16, (int) counts.get("fcc9c3"));
		assertEquals(4, (int) counts.get("00c9c3"));
		assertEquals(2, (int) counts.get("01c9c3"));
	}

	@Test
	public void testReturnBytesSize() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		List<ByteSequenceRowObject> returnBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.RETURN, null, null);
		int total = 0;

		//in the test data, the functions at address 0xf have two returns
		for (ByteSequenceRowObject row : returnBytes) {
			total += row.getNumOccurrences();
			double percentage = (100.0 * row.getNumOccurrences()) / (TOTAL_NUM_FUNCTIONS + 2);
			assertEquals(percentage, row.getPercentage(), Double.NaN);
		}
		assertEquals(total, (TOTAL_NUM_FUNCTIONS + 2));
	}

	@Test
	public void testReturnBytesContextRegisterFiltering() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		List<ByteSequenceRowObject> returnBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.RETURN, null, null);
		ContextRegisterFilter cRegFilter = new ContextRegisterFilter();
		cRegFilter.addRegAndValueToFilter("cReg1", new BigInteger("0"));
		cRegFilter.addRegAndValueToFilter("cReg2", new BigInteger("1"));
		cRegFilter.addRegAndValueToFilter("cReg3", new BigInteger("3"));
		cRegFilter.addRegAndValueToFilter("cReg4", new BigInteger("7"));

		returnBytes = ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.RETURN,
			cRegFilter, null);
		assertEquals(returnBytes.size(), 2);
		for (ByteSequenceRowObject row : returnBytes) {
			switch (row.getNumOccurrences()) {
				case 2:
					assertEquals(row.getDisassembly(), " ADD:3(EAX,0x1)  LEAVE:1()  RET:1() ");
					break;
				case 4:
					assertEquals(row.getDisassembly(), " POP:1(RBX)  LEAVE:1()  RET:1() ");
					break;
				default:
					fail();
			}
		}
	}

	@Test
	public void testReturnBytesLengthFiltering() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		List<ByteSequenceRowObject> returnBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.RETURN, null, null);
		ByteSequenceLengthFilter lFilter = new ByteSequenceLengthFilter(-2, 2);
		returnBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.RETURN, null, lFilter);
		assertEquals(returnBytes.size(), 1);
		assertEquals(returnBytes.get(0).getSequence(), "c9c3");

		lFilter = new ByteSequenceLengthFilter(-3, 3);
		returnBytes =
			ByteSequenceRowObject.getFilteredRowObjects(fInfo, PatternType.RETURN, null, lFilter);
		assertEquals(returnBytes.size(), 7);

		Map<String, Integer> counts = new HashMap<>();
		for (ByteSequenceRowObject row : returnBytes) {
			counts.put(row.getSequence(), row.getNumOccurrences());
		}
		assertEquals(14, (int) counts.get("fcc9c3"));
		assertEquals(6, (int) counts.get("01c9c3"));
		assertEquals(4, (int) counts.get("5bc9c3"));
	}

	@Test
	public void testBasicMerge() {
		List<ByteSequenceRowObject> seqs = new ArrayList<>();
		seqs.add(new ByteSequenceRowObject("554889e548", null, 1, 0.3));
		seqs.add(new ByteSequenceRowObject("554889e553", null, 1, 0.3));
		seqs.add(new ByteSequenceRowObject("554889e589", null, 1, 0.3));

		DittedBitSequence lub = ByteSequenceRowObject.merge(seqs);
		String pattern = lub.getHexString();
		assertEquals(pattern, "0x55 0x48 0x89 0xe5 ..0..0..");
		assertEquals(lub.getNumUncertainBits(), 6);
		assertEquals(lub.getNumFixedBits(), 34);
	}

	@Test
	public void testNullMerge() {
		assertEquals(null, ByteSequenceRowObject.merge(null));
	}

	@Test
	public void testEmptyMerge() {
		assertEquals(null, ByteSequenceRowObject.merge(new ArrayList<ByteSequenceRowObject>()));
	}

	@Test
	public void testFirstInstructions() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		List<String> instructions = new ArrayList<>();
		List<Integer> lengths = new ArrayList<>();
		instructions.add("PUSH");
		instructions.add("MOV");
		instructions.add("MOV");
		lengths.add(1);
		lengths.add(3);
		lengths.add(4);
		InstructionSequenceTreePathFilter pathFilter =
			new InstructionSequenceTreePathFilter(instructions, lengths, PatternType.FIRST);
		List<ByteSequenceRowObject> rows =
			ByteSequenceRowObject.getRowObjectsFromInstructionSequences(fInfo, pathFilter, null);
		assertEquals(rows.size(), 1);
		assertEquals(rows.get(0).getNumOccurrences(), 2);
		assertEquals(rows.get(0).getDisassembly(),
			" PUSH:1(RBP)  MOV:3(RBP,RSP)  MOV:4([RBP + -0x8],RDI) ");
		assertEquals(rows.get(0).getPercentage(), 100.0, Double.NaN);
		assertEquals(rows.get(0).getSequence(), "554889e548897df8");
	}

	@Test
	public void testPreInstructions() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		List<String> instructions = new ArrayList<>();
		List<Integer> lengths = new ArrayList<>();
		instructions.add("RET");
		instructions.add("LEAVE");
		instructions.add("ADD");
		lengths.add(1);
		lengths.add(1);
		lengths.add(3);
		InstructionSequenceTreePathFilter pathFilter =
			new InstructionSequenceTreePathFilter(instructions, lengths, PatternType.PRE);
		List<ByteSequenceRowObject> rows =
			ByteSequenceRowObject.getRowObjectsFromInstructionSequences(fInfo, pathFilter, null);
		assertEquals(rows.size(), 4);
		Set<String> bytes = new HashSet<>();
		Set<String> dis = new HashSet<>();
		for (ByteSequenceRowObject row : rows) {
			assertEquals(row.getNumOccurrences(), 2);
			assertEquals(row.getPercentage(), 25.0, Double.NaN);
			bytes.add(row.getSequence());
			dis.add(row.getDisassembly());
		}
		assertEquals(bytes.size(), 4);
		assertEquals(dis.size(), 4);

		assertTrue(bytes.contains("0345fcc9c3"));
		assertTrue(bytes.contains("83c003c9c3"));
		assertTrue(bytes.contains("83c002c9c3"));
		assertTrue(bytes.contains("83c001c9c3"));

		assertTrue(dis.contains(" ADD:3(EAX,[RBP + -0x4])  LEAVE:1()  RET:1() "));
		assertTrue(dis.contains(" ADD:3(EAX,0x3)  LEAVE:1()  RET:1() "));
		assertTrue(dis.contains(" ADD:3(EAX,0x2)  LEAVE:1()  RET:1() "));
		assertTrue(dis.contains(" ADD:3(EAX,0x1)  LEAVE:1()  RET:1() "));
	}

	@Test
	public void testReturnInstructions() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		List<String> instructions = new ArrayList<>();
		List<Integer> lengths = new ArrayList<>();
		instructions.add("RET");
		instructions.add("LEAVE");
		lengths.add(1);
		lengths.add(1);
		InstructionSequenceTreePathFilter pathFilter =
			new InstructionSequenceTreePathFilter(instructions, lengths, PatternType.RETURN);
		List<ByteSequenceRowObject> rows =
			ByteSequenceRowObject.getRowObjectsFromInstructionSequences(fInfo, pathFilter, null);
		assertEquals(rows.size(), 1);
		assertEquals(rows.get(0).getDisassembly(), " LEAVE:1()  RET:1() ");
		assertEquals(rows.get(0).getNumOccurrences(), 34);
		assertEquals(rows.get(0).getPercentage(), 100.0, Double.NaN);
		assertEquals(rows.get(0).getSequence(), "c9c3");
	}

	@Test
	public void testContextRegisterFiltering() {
		List<FunctionBitPatternInfo> fInfo = fReader.getFInfoList();
		List<String> instructions = new ArrayList<>();
		List<Integer> lengths = new ArrayList<>();
		instructions.add("PUSH");
		instructions.add("MOV");
		instructions.add("SUB");
		lengths.add(1);
		lengths.add(3);
		lengths.add(4);
		InstructionSequenceTreePathFilter pathFilter =
			new InstructionSequenceTreePathFilter(instructions, lengths, PatternType.FIRST);
		ContextRegisterFilter cRegFilter = new ContextRegisterFilter();
		BigInteger zero = new BigInteger("0");
		cRegFilter.addRegAndValueToFilter("cReg1", zero);
		cRegFilter.addRegAndValueToFilter("cReg2", zero);
		cRegFilter.addRegAndValueToFilter("cReg3", zero);
		cRegFilter.addRegAndValueToFilter("cReg4", zero);
		List<ByteSequenceRowObject> rows =
			ByteSequenceRowObject.getRowObjectsFromInstructionSequences(fInfo, pathFilter,
				cRegFilter);
		assertEquals(rows.size(), 2);
		Set<String> bytes = new HashSet<>();
		Set<String> dis = new HashSet<>();
		for (ByteSequenceRowObject row : rows) {
			assertEquals(2, row.getNumOccurrences());
			assertEquals(row.getPercentage(), 50.0, Double.NaN);
			bytes.add(row.getSequence());
			dis.add(row.getDisassembly());
		}
		assertEquals(bytes.size(), 2);
		assertEquals(dis.size(), 2);
		assertTrue(bytes.contains("554889e54883ec30"));
		assertTrue(bytes.contains("554889e54883ec20"));
		assertTrue(dis.contains(" PUSH:1(RBP)  MOV:3(RBP,RSP)  SUB:4(RSP,0x30) "));
		assertTrue(dis.contains(" PUSH:1(RBP)  MOV:3(RBP,RSP)  SUB:4(RSP,0x20) "));
	}

}
