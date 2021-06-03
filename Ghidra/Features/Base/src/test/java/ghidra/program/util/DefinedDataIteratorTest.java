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

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import util.CollectionUtils;

public class DefinedDataIteratorTest extends AbstractGhidraHeadlessIntegrationTest {

	private ToyProgramBuilder builder;
	private ProgramDB program;
	private DataTypeManager dtm;
	private DataType intDT;
	private StringDataType stringDT;
	private CharDataType charDT;
	private DataType charArray;
	private StructureDataType struct1DT;
	private ArrayDataType structArray;
	private StructureDataType struct2DT;
	private TypeDef intTD;

	@Before
	public void setUp() throws Exception {

		builder = new ToyProgramBuilder("DefinedDataIteratorTests", false);
		program = builder.getProgram();
		dtm = program.getDataTypeManager();

		intDT = AbstractIntegerDataType.getSignedDataType(4, dtm);
		intTD = new TypedefDataType("int_typedef", intDT);
		stringDT = StringDataType.dataType;
		charDT = new CharDataType(dtm);
		charArray = new ArrayDataType(charDT, 20, charDT.getLength());

		struct1DT = new StructureDataType("struct1", 100);
		struct1DT.replaceAtOffset(0, intDT, intDT.getLength(), "f1", null);
		struct1DT.replaceAtOffset(10, charArray, charArray.getLength(), "f2", null);
		struct1DT.replaceAtOffset(50, stringDT, 10, "f3", null);

		structArray = new ArrayDataType(struct1DT, 10, struct1DT.getLength());

		struct2DT = new StructureDataType("struct2", 200);
		struct2DT.replaceAtOffset(0, intDT, intDT.getLength(), "f1", null);
		struct2DT.replaceAtOffset(10, struct1DT, intDT.getLength(), "f2", null);

		builder.createMemory("test", "0x0", 0x2000);
		program = builder.getProgram();
	}

	@Test
	public void test_Ints() throws Exception {
		builder.applyFixedLengthDataType("0x0", intDT, intDT.getLength());
		builder.createString("0x10", "test1", StandardCharsets.UTF_8, true, stringDT);
		builder.applyFixedLengthDataType("0x100", struct1DT, struct1DT.getLength());

		List<Data> list = CollectionUtils.asList((Iterable<Data>)
			DefinedDataIterator.byDataType(program, dt -> dt instanceof IntegerDataType));

		assertTrue(list.get(0).getAddress().getOffset() == 0x0);
		assertTrue(list.get(1).getAddress().getOffset() == 0x100);

		assertEquals(2, list.size());
	}

	@Test
	public void test_Strings() throws Exception {
		builder.applyFixedLengthDataType("0x0", intDT, intDT.getLength());
		builder.createString("0x10", "test1", StandardCharsets.UTF_8, true, stringDT);
		builder.applyFixedLengthDataType("0x100", struct1DT, struct1DT.getLength());

		List<Data> list =
			CollectionUtils.asList((Iterable<Data>) DefinedDataIterator.definedStrings(program));

		assertTrue(list.get(0).getAddress().getOffset() == 0x10);
		assertTrue(list.get(1).getAddress().getOffset() == 0x100 + 10);
		assertTrue(list.get(2).getAddress().getOffset() == 0x100 + 50);

		assertEquals(3, list.size());
	}

	@Test
	public void test_ArrayOfStructs() throws Exception {
		builder.applyFixedLengthDataType("0x0", intDT, intDT.getLength());
		builder.createString("0x10", "test1", StandardCharsets.UTF_8, true, stringDT);
		builder.applyFixedLengthDataType("0x100", structArray, structArray.getLength());

		int numElements = structArray.getNumElements();
		int lastEle = numElements - 1;
		int elementSize = structArray.getElementLength();

		List<Data> list =
			CollectionUtils.asList((Iterable<Data>) DefinedDataIterator.definedStrings(program));

		assertEquals(list.get(0).getAddress().getOffset(), 0x10);
		assertEquals(list.get(1 + 0).getAddress().getOffset(), 0x100 + 10);
		assertEquals(list.get(1 + 1).getAddress().getOffset(), 0x100 + 50);

		assertEquals(list.get(1 + (lastEle * 2) + 0).getAddress().getOffset(),
			0x100 + (elementSize * lastEle) + 10);
		assertEquals(list.get(1 + (lastEle * 2) + 1).getAddress().getOffset(),
			0x100 + (elementSize * lastEle) + 50);

		assertEquals(1 + (numElements * 2), list.size());
	}

	@Test
	public void test_Typedefs() throws CodeUnitInsertionException {
		// 3 ints: 2 are typedefs, 1 is regular int
		builder.applyFixedLengthDataType("0x0", intTD, intTD.getLength());
		builder.applyFixedLengthDataType("0x10", intTD, intTD.getLength());
		builder.applyFixedLengthDataType("0x20", intDT, intTD.getLength());

		// iterating by data type ignores typedefs, so we should get all 3 ints
		List<Data> list = CollectionUtils.asList((Iterable<Data>)
			DefinedDataIterator.byDataType(program, dt -> dt instanceof IntegerDataType));

		assertEquals(3, list.size());

		// iterating by data instance, we can inspect the actual data type and get the
		// typedef
		list = CollectionUtils.asList((Iterable<Data>) DefinedDataIterator.byDataInstance(program,
			data -> data.getDataType() instanceof TypeDef));
		assertEquals(2, list.size());
	}
}
