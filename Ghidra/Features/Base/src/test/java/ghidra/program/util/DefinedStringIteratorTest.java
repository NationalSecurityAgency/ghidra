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
package ghidra.program.util;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.apache.commons.collections4.IteratorUtils;
import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;

public class DefinedStringIteratorTest extends AbstractGhidraHeadlessIntegrationTest {

	private ToyProgramBuilder builder;
	private ProgramDB program;
	private DataTypeManager dtm;
	private DataType intDT;
	private StringDataType stringDT;
	private CharDataType charDT;
	private DataType charArray;
	private StructureDataType struct1DT;
	private int s1f2Offset = 10;
	private int s1f3Offset = 50;
	private ArrayDataType structArray;
	private StructureDataType struct2DT;
	private StructureDataType struct3DT;

	@Before
	public void setUp() throws Exception {

		builder = new ToyProgramBuilder("DefinedStringIteratorTests", false);
		program = builder.getProgram();
		dtm = program.getDataTypeManager();

		intDT = AbstractIntegerDataType.getSignedDataType(4, dtm);
		stringDT = StringDataType.dataType;
		charDT = new CharDataType(dtm);
		charArray = new ArrayDataType(charDT, 20);

		struct1DT = new StructureDataType("struct1", 100);
		struct1DT.replaceAtOffset(0, intDT, -1, "f1", null);
		struct1DT.replaceAtOffset(s1f2Offset, charArray, -1, "f2", null);
		struct1DT.replaceAtOffset(s1f3Offset, stringDT, 10, "f3", null);

		structArray = new ArrayDataType(struct1DT, 10, -1);

		struct2DT = new StructureDataType("struct2", 200);
		struct2DT.replaceAtOffset(0, intDT, -1, "f1", null);
		struct2DT.replaceAtOffset(10, struct1DT, -1, "f2", null);

		struct3DT = new StructureDataType("struct3", 200);
		struct3DT.replaceAtOffset(0, charArray, -1, "f1", null);

		builder.createMemory("test", "0x0", 0x20000);
		program = builder.getProgram();
	}

	private String addrStr(long offset) {
		return builder.getAddress(offset).toString();
	}

	@Test
	public void test_Strings() throws Exception {
		int str1Addr = 0x10;
		int struct1Addr = 0x100;

		builder.applyFixedLengthDataType("0x0", intDT, -1);
		builder.createString(addrStr(str1Addr), "test1", StandardCharsets.UTF_8, true, stringDT);
		builder.applyFixedLengthDataType(addrStr(struct1Addr), struct1DT, -1);

		List<Data> list = IteratorUtils.toList(DefinedStringIterator.forProgram(program));

		assertEquals(str1Addr, list.get(0).getAddress().getOffset());
		assertEquals(struct1Addr + s1f2Offset, list.get(1).getAddress().getOffset());
		assertEquals(struct1Addr + s1f3Offset, list.get(2).getAddress().getOffset());

		assertEquals(3, list.size());
	}

	@Test
	public void test_AllowIteratorNextWithoutHasNextIck() throws Exception {
		int str1Addr = 0x10;
		int struct1Addr = 0x100;

		builder.applyFixedLengthDataType("0x0", intDT, -1);
		builder.createString(addrStr(str1Addr), "test1", StandardCharsets.UTF_8, true, stringDT);
		builder.applyFixedLengthDataType(addrStr(struct1Addr), struct1DT, -1);

		DefinedStringIterator it = DefinedStringIterator.forProgram(program);

		assertEquals(str1Addr, it.next().getAddress().getOffset());
		assertEquals(struct1Addr + s1f2Offset, it.next().getAddress().getOffset());
		assertEquals(struct1Addr + s1f3Offset, it.next().getAddress().getOffset());

		assertFalse(it.hasNext());
	}

	@Test
	public void test_ArrayOfStructs() throws Exception {
		int str1Addr = 0x10;
		int s1ArrayAddr = 0x100;

		builder.applyFixedLengthDataType("0x0", intDT, -1);
		builder.createString(addrStr(str1Addr), "test1", StandardCharsets.UTF_8, true, stringDT);
		builder.applyFixedLengthDataType(addrStr(s1ArrayAddr), structArray, -1);

		int numElements = structArray.getNumElements();
		int lastEle = numElements - 1;
		int elementSize = structArray.getElementLength();

		List<Data> list = IteratorUtils.toList(DefinedStringIterator.forProgram(program));

		assertEquals(str1Addr, list.get(0).getAddress().getOffset());

		int s1ArrayElemIndex = 1;
		assertEquals(arrayElementAddr(s1ArrayAddr, elementSize, 0) + s1f2Offset,
			list.get(s1ArrayElemIndex + 0).getAddress().getOffset());
		assertEquals(arrayElementAddr(s1ArrayAddr, elementSize, 0) + s1f3Offset,
			list.get(s1ArrayElemIndex + 1).getAddress().getOffset());

		s1ArrayElemIndex = s1ArrayElemIndex + (lastEle * 2 /* 2 strs per struct */);
		assertEquals(arrayElementAddr(s1ArrayAddr, elementSize, lastEle) + s1f2Offset,
			list.get(s1ArrayElemIndex + 0).getAddress().getOffset());
		assertEquals(arrayElementAddr(s1ArrayAddr, elementSize, lastEle) + s1f3Offset,
			list.get(s1ArrayElemIndex + 1).getAddress().getOffset());

		assertEquals(s1ArrayElemIndex + 2, list.size());
	}

	@Test
	public void test_StructFirstField() throws Exception {
		// ensure we get the first field of a struct

		int structAddr = 0x100;

		builder.applyFixedLengthDataType(addrStr(structAddr), struct3DT, -1);

		DefinedStringIterator it = DefinedStringIterator.forProgram(program);
		List<Data> list = IteratorUtils.toList(it);
		assertEquals(1, list.size());
	}

	private long arrayElementAddr(long arrayAddr, int elemSize, int elemIndex) {
		return arrayAddr + (elemSize * elemIndex);
	}

	@Test
	public void test_DontLookAtArrayElements() throws Exception {
		int str1Addr = 0x10;
		int s1ArrayAddr = 0x100;

		builder.applyFixedLengthDataType("0x0", intDT, -1); // +1 candidate count 
		builder.createString(addrStr(str1Addr), "test1", StandardCharsets.UTF_8, true, stringDT); // +1
		builder.applyFixedLengthDataType(addrStr(s1ArrayAddr), structArray, -1); // +(1 + 10 + 10*3)

		DataType byteArray = new ArrayDataType(ByteDataType.dataType, 2000, -1);
		builder.applyFixedLengthDataType("0x1000", byteArray, -1); // +1

		DefinedStringIterator it = DefinedStringIterator.forProgram(program);
		List<Data> list = IteratorUtils.toList(it);

		assertEquals(44, it.getDataCandidateCount()); // 1 + 1 + 1 + 10 + 10*3
		assertEquals(21, list.size()); // 1 ds@0x10 + 2 per structArray element
	}
}
