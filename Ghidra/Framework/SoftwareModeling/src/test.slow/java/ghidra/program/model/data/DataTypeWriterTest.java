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
package ghidra.program.model.data;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.StringWriter;

import org.junit.*;

import generic.test.AbstractGTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class DataTypeWriterTest extends AbstractGTest {

	private static String EOL = System.getProperty("line.separator");

	private StringWriter writer;
	private DataTypeWriter dtWriter;

	public DataTypeWriterTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		writer = new StringWriter();
		dtWriter = new DataTypeWriter(null, writer); // uses default data organization
	}

	@After
	public void tearDown() throws Exception {

		writer.close();
	}

	@Test
	public void testTypeDef() throws IOException, CancelledException {
		TypeDef typedef = new TypedefDataType("BOB", new CharDataType());
		dtWriter.write(typedef, TaskMonitorAdapter.DUMMY_MONITOR);
		String actual = writer.getBuffer().toString();
		String expected = "typedef char BOB;" + EOL + EOL;
		assertEquals(expected, actual);
	}

	@Test
	public void testTypeDef2() throws IOException, CancelledException {
		TypeDef typedef = new TypedefDataType("unsigned int", new DWordDataType());
		dtWriter.write(typedef, TaskMonitorAdapter.DUMMY_MONITOR);
		String actual = writer.getBuffer().toString();
		String expected = "";
		assertEquals(expected, actual);
	}

	@Test
	public void testTypeDef3() throws IOException, CancelledException {
		TypeDef typedef = new TypedefDataType("const float", new DWordDataType());
		dtWriter.write(typedef, TaskMonitorAdapter.DUMMY_MONITOR);
		String actual = writer.getBuffer().toString();
		String expected = "";
		assertEquals(expected, actual);
	}

	@Test
	public void testTypeDef4() throws IOException, CancelledException {
		Structure struct = new StructureDataType("MyBasicStruct", 0);
		struct.add(new CharDataType());
		struct.add(new ByteDataType());

		Pointer pointer1 = PointerDataType.getPointer(struct, 4);

		Pointer pointer2 = PointerDataType.getPointer(pointer1, 4);

		TypeDef typedef =
			new TypedefDataType("static const " + pointer2.getDisplayName(), pointer2);
		dtWriter.write(typedef, TaskMonitorAdapter.DUMMY_MONITOR);
		String actual = writer.getBuffer().toString();
		String expected = "";
		assertEquals(expected, actual);
	}

	@Test
	public void testEnum() throws IOException, CancelledException {
		Enum enumm = new EnumDataType("myEnum", 1);
		enumm.add("A", 0);
		enumm.add("B", 1);
		enumm.add("C", 2);
		enumm.add("D", 3);
		enumm.add("E", 4);
		dtWriter.write(enumm, TaskMonitorAdapter.DUMMY_MONITOR);
		String actual = writer.getBuffer().toString();
		String expected = "typedef enum myEnum {" + EOL + "    A=0," + EOL + "    B=1," + EOL +
			"    C=2," + EOL + "    D=3," + EOL + "    E=4" + EOL + "} myEnum;" + EOL + EOL;
		assertEquals(expected, actual);
	}

	@Test
	public void testEnum2() throws IOException, CancelledException {
		Enum enumm = new EnumDataType("myEnum", 1);
		enumm.add("A", 4);
		enumm.add("B", 8);
		enumm.add("C", 16);
		enumm.add("D", 32);
		enumm.add("E", 254);
		dtWriter.write(enumm, TaskMonitorAdapter.DUMMY_MONITOR);
		String actual = writer.getBuffer().toString();
		String expected = "typedef enum myEnum {" + EOL + "    A=4," + EOL + "    B=8," + EOL +
			"    C=16," + EOL + "    D=32," + EOL + "    E=254" + EOL + "} myEnum;" + EOL + EOL;
		assertEquals(expected, actual);
	}

	@Test
	public void testStructure() throws IOException, CancelledException {
		Structure struct = new StructureDataType("MyStruct", 0);
		struct.setDescription("this is my structure");
		struct.add(new CharDataType(), "myChar", "this is a character");
		struct.add(new ByteDataType(), "myByte", "this is a byte");
		struct.add(new WordDataType(), "myWord", "this is a word");
		struct.add(new DWordDataType(), "myDWord", "this is a dword");
		struct.add(new QWordDataType(), "myQWord", "this is a qword");
		struct.add(new FloatDataType(), "myFloat", "this is a float");
		struct.add(new DoubleDataType(), "myDouble", "this is a double");
		struct.add(PointerDataType.getPointer(new FloatDataType(), 4), "myFloatPointer",
			"this is a float pointer");
		struct.setFlexibleArrayComponent(new CharDataType(), "myFlexArray", "this is a flex array");
		dtWriter.write(struct, TaskMonitorAdapter.DUMMY_MONITOR);
		String actual = writer.getBuffer().toString();
		String expected = "typedef struct MyStruct MyStruct, *PMyStruct;" + EOL + EOL +
			"typedef unsigned char    byte;" + EOL + "typedef unsigned short    word;" + EOL +
			"typedef unsigned int    dword;" + EOL + "typedef unsigned long long    qword;" + EOL +
			"struct MyStruct { /* this is my structure */" + EOL +
			"    char myChar; /* this is a character */" + EOL +
			"    byte myByte; /* this is a byte */" + EOL +
			"    word myWord; /* this is a word */" + EOL +
			"    dword myDWord; /* this is a dword */" + EOL +
			"    qword myQWord; /* this is a qword */" + EOL +
			"    float myFloat; /* this is a float */" + EOL +
			"    double myDouble; /* this is a double */" + EOL +
			"    float * myFloatPointer; /* this is a float pointer */" + EOL +
			"    char[0] myFlexArray; /* this is a flex array */" + EOL + "};" + EOL + EOL;
		assertEquals(expected, actual);
	}

	@Test
	public void testStructureBasic() throws IOException, CancelledException {
		Structure struct = new StructureDataType("MyBasicStruct", 0);
		struct.add(new CharDataType());
		struct.add(new ByteDataType());
		struct.add(new WordDataType());
		struct.add(new DWordDataType());
		struct.add(new QWordDataType());
		struct.add(new FloatDataType());
		struct.add(new DoubleDataType());
		struct.add(PointerDataType.getPointer(new FloatDataType(), 4));
		dtWriter.write(struct, TaskMonitorAdapter.DUMMY_MONITOR);
		String actual = writer.getBuffer().toString();
		String expected = "typedef struct MyBasicStruct MyBasicStruct, *PMyBasicStruct;" + EOL +
			EOL + "typedef unsigned char    byte;" + EOL + "typedef unsigned short    word;" + EOL +
			"typedef unsigned int    dword;" + EOL + "typedef unsigned long long    qword;" + EOL +
			"struct MyBasicStruct {" + EOL + "    char field_0x0;" + EOL + "    byte field_0x1;" +
			EOL + "    word field_0x2;" + EOL + "    dword field_0x4;" + EOL +
			"    qword field_0x8;" + EOL + "    float field_0x10;" + EOL +
			"    double field_0x14;" + EOL + "    float * field_0x1c;" + EOL + "};" + EOL + EOL;
		assertEquals(expected, actual);
	}

	@Test
	public void testStructureInStructure() throws IOException, CancelledException {
		Structure innerStructure = new StructureDataType("MyInnerStructure", 0);
		innerStructure.setDescription("this is my inner structure");
		innerStructure.add(new CharDataType(), "myInnerChar", "this is a inner character");
		innerStructure.add(new ByteDataType(), "myInnerByte", "this is a inner byte");

		Structure outerStructure = new StructureDataType("MyOuterStructure", 0);
		outerStructure.setDescription("this is my outer structure");
		outerStructure.add(new FloatDataType(), "myOuterFloat", "this is a outer float");
		outerStructure.add(new TypedefDataType("int", new DWordDataType()), "myOuterInt",
			"this is a outer int");
		outerStructure.add(innerStructure, "myOuterInnerStructure",
			"this is a outer inner structure");
		outerStructure.add(new CharDataType(), "myOuterChar", "this is a outer character");

		dtWriter.write(outerStructure, TaskMonitorAdapter.DUMMY_MONITOR);

		String actual = writer.getBuffer().toString();

		String expected = "typedef struct MyOuterStructure MyOuterStructure, *PMyOuterStructure;" +
			EOL + EOL + "typedef struct MyInnerStructure MyInnerStructure, *PMyInnerStructure;" +
			EOL + EOL + "typedef unsigned char    byte;" + EOL +
			"struct MyInnerStructure { /* this is my inner structure */" + EOL +
			"    char myInnerChar; /* this is a inner character */" + EOL +
			"    byte myInnerByte; /* this is a inner byte */" + EOL + "};" + EOL + EOL +
			"struct MyOuterStructure { /* this is my outer structure */" + EOL +
			"    float myOuterFloat; /* this is a outer float */" + EOL +
			"    int myOuterInt; /* this is a outer int */" + EOL +
			"    struct MyInnerStructure myOuterInnerStructure; /* this is a outer inner structure */" +
			EOL + "    char myOuterChar; /* this is a outer character */" + EOL + "};" + EOL + EOL;

		assertEquals(expected, actual);
	}

	@Test
	public void testStructureInUnion() throws IOException, CancelledException {
		Structure innerStructure = new StructureDataType("MyInnerStructure", 0);
		innerStructure.setDescription("this is my inner structure");
		innerStructure.add(new CharDataType(), "myInnerChar", "this is a inner character");
		innerStructure.add(new ByteDataType(), "myInnerByte", "this is a inner byte");

		Union outerUnion = new UnionDataType("MyOuterUnion");
		outerUnion.setDescription("this is my outer union");
		outerUnion.add(new FloatDataType(), "myOuterFloat", "this is a outer float");
		outerUnion.add(new TypedefDataType("int", new DWordDataType()), "myOuterInt",
			"this is a outer int");
		outerUnion.add(innerStructure, "myOuterInnerStructure", "this is a outer inner structure");
		outerUnion.add(new CharDataType(), "myOuterChar", "this is a outer character");

		dtWriter.write(outerUnion, TaskMonitorAdapter.DUMMY_MONITOR);

		String actual = writer.getBuffer().toString();

		String expected = "typedef union MyOuterUnion MyOuterUnion, *PMyOuterUnion;" + EOL + EOL +
			"typedef struct MyInnerStructure MyInnerStructure, *PMyInnerStructure;" + EOL + EOL +
			"typedef unsigned char    byte;" + EOL +
			"struct MyInnerStructure { /* this is my inner structure */" + EOL +
			"    char myInnerChar; /* this is a inner character */" + EOL +
			"    byte myInnerByte; /* this is a inner byte */" + EOL + "};" + EOL + EOL +
			"union MyOuterUnion { /* this is my outer union */" + EOL +
			"    float myOuterFloat; /* this is a outer float */" + EOL +
			"    int myOuterInt; /* this is a outer int */" + EOL +
			"    struct MyInnerStructure myOuterInnerStructure; /* this is a outer inner structure */" +
			EOL + "    char myOuterChar; /* this is a outer character */" + EOL + "};" + EOL + EOL;

		assertEquals(expected, actual);
	}

	@Test
	public void testStructureSelfReference() throws IOException, CancelledException {
		Structure struct = new StructureDataType("MySelfRefStruct", 0);
		struct.add(new WordDataType());
		struct.add(PointerDataType.getPointer(struct, 4));
		struct.add(new DoubleDataType());

		dtWriter.write(struct, TaskMonitorAdapter.DUMMY_MONITOR);
		String actual = writer.getBuffer().toString();
		String expected = "typedef struct MySelfRefStruct MySelfRefStruct, *PMySelfRefStruct;" +
			EOL + EOL + "typedef unsigned short    word;" + EOL + "struct MySelfRefStruct {" + EOL +
			"    word field_0x0;" + EOL + "    struct MySelfRefStruct * field_0x2;" + EOL +
			"    double field_0x6;" + EOL + "};" + EOL + EOL;

		assertEquals(expected, actual);
	}

	@Test
	public void testUnion() throws IOException, CancelledException {
		Union union = new UnionDataType("MyUnion");
		union.setDescription("this is my union");
		union.add(new CharDataType(), "myChar", "this is a character");
		union.add(new ByteDataType(), "myByte", "this is a byte");
		union.add(new WordDataType(), "myWord", "this is a word");
		union.add(new DWordDataType(), "myDWord", "this is a dword");
		union.add(new QWordDataType(), "myQWord", "this is a qword");
		union.add(new FloatDataType(), "myFloat", "this is a float");
		union.add(new DoubleDataType(), "myDouble", "this is a double");
		union.add(PointerDataType.getPointer(new FloatDataType(), 4), "myFloatPointer",
			"this is a float pointer");
		dtWriter.write(union, TaskMonitorAdapter.DUMMY_MONITOR);
		String actual = writer.getBuffer().toString();
		String expected = "typedef union MyUnion MyUnion, *PMyUnion;" + EOL + EOL +
			"typedef unsigned char    byte;" + EOL + "typedef unsigned short    word;" + EOL +
			"typedef unsigned int    dword;" + EOL + "typedef unsigned long long    qword;" + EOL +
			"union MyUnion { /* this is my union */" + EOL +
			"    char myChar; /* this is a character */" + EOL +
			"    byte myByte; /* this is a byte */" + EOL +
			"    word myWord; /* this is a word */" + EOL +
			"    dword myDWord; /* this is a dword */" + EOL +
			"    qword myQWord; /* this is a qword */" + EOL +
			"    float myFloat; /* this is a float */" + EOL +
			"    double myDouble; /* this is a double */" + EOL +
			"    float * myFloatPointer; /* this is a float pointer */" + EOL + "};" + EOL + EOL;

		assertEquals(expected, actual);
	}

	@Test
	public void testUnionInUnion() throws IOException, CancelledException {
		Union innerUnion = new UnionDataType("MyInnerUnion");
		innerUnion.setDescription("this is my inner union");
		innerUnion.add(new CharDataType(), "myInnerChar", "this is a inner character");
		innerUnion.add(new ByteDataType(), "myInnerByte", "this is a inner byte");

		Union outerUnion = new UnionDataType("MyOuterUnion");
		outerUnion.setDescription("this is my outer union");
		outerUnion.add(new FloatDataType(), "myOuterFloat", "this is a outer float");
		outerUnion.add(new TypedefDataType("int", new DWordDataType()), "myOuterInt",
			"this is a outer int");
		outerUnion.add(innerUnion, "myOuterInnerUnion", "this is a outer inner union");
		outerUnion.add(new CharDataType(), "myOuterChar", "this is a outer character");

		dtWriter.write(outerUnion, TaskMonitorAdapter.DUMMY_MONITOR);

		String actual = writer.getBuffer().toString();

		String expected = "typedef union MyOuterUnion MyOuterUnion, *PMyOuterUnion;" + EOL + EOL +
			"typedef union MyInnerUnion MyInnerUnion, *PMyInnerUnion;" + EOL + EOL +
			"typedef unsigned char    byte;" + EOL +
			"union MyInnerUnion { /* this is my inner union */" + EOL +
			"    char myInnerChar; /* this is a inner character */" + EOL +
			"    byte myInnerByte; /* this is a inner byte */" + EOL + "};" + EOL + EOL +
			"union MyOuterUnion { /* this is my outer union */" + EOL +
			"    float myOuterFloat; /* this is a outer float */" + EOL +
			"    int myOuterInt; /* this is a outer int */" + EOL +
			"    union MyInnerUnion myOuterInnerUnion; /* this is a outer inner union */" + EOL +
			"    char myOuterChar; /* this is a outer character */" + EOL + "};" + EOL + EOL;

		assertEquals(expected, actual);
	}

	@Test
	public void testUnionInStructure() throws IOException, CancelledException {
		Union innerUnion = new UnionDataType("MyInnerUnion");
		innerUnion.setDescription("this is my inner union");
		innerUnion.add(new CharDataType(), "myInnerChar", "this is a inner character");
		innerUnion.add(new ByteDataType(), "myInnerByte", "this is a inner byte");

		Structure outerStructure = new StructureDataType("MyOuterStructure", 0);
		outerStructure.setDescription("this is my outer structure");
		outerStructure.add(new FloatDataType(), "myOuterFloat", "this is a outer float");
		outerStructure.add(new TypedefDataType("int", new DWordDataType()), "myOuterInt",
			"this is a outer int");
		outerStructure.add(innerUnion, "myOuterInnerUnion", "this is a outer inner union");
		outerStructure.add(new CharDataType(), "myOuterChar", "this is a outer character");

		dtWriter.write(outerStructure, TaskMonitorAdapter.DUMMY_MONITOR);

		String actual = writer.getBuffer().toString();

		String expected = "typedef struct MyOuterStructure MyOuterStructure, *PMyOuterStructure;" +
			EOL + EOL + "typedef union MyInnerUnion MyInnerUnion, *PMyInnerUnion;" + EOL + EOL +
			"typedef unsigned char    byte;" + EOL +
			"union MyInnerUnion { /* this is my inner union */" + EOL +
			"    char myInnerChar; /* this is a inner character */" + EOL +
			"    byte myInnerByte; /* this is a inner byte */" + EOL + "};" + EOL + EOL +
			"struct MyOuterStructure { /* this is my outer structure */" + EOL +
			"    float myOuterFloat; /* this is a outer float */" + EOL +
			"    int myOuterInt; /* this is a outer int */" + EOL +
			"    union MyInnerUnion myOuterInnerUnion; /* this is a outer inner union */" + EOL +
			"    char myOuterChar; /* this is a outer character */" + EOL + "};" + EOL + EOL;

		assertEquals(expected, actual);
	}

	@Test
	public void testArray() {
		//TODO
	}

	@Test
	public void testSizableDynamicInStructure() throws IOException, CancelledException {
		Structure struct = new StructureDataType("MyStruct", 0);
		struct.setDescription("this is my structure");
		struct.add(new QWordDataType(), "myQWord", "this is my qword");
		struct.add(new StringDataType(), 10, "myStr", "this is my string");
		struct.add(new DoubleDataType(), "myDouble", "this is my double");
		struct.add(PointerDataType.getPointer(new FloatDataType(), 4), "myFloatPointer",
			"this is my float pointer");

		dtWriter.write(struct, TaskMonitorAdapter.DUMMY_MONITOR);

		String actual = writer.getBuffer().toString();

		String expected = "typedef struct MyStruct MyStruct, *PMyStruct;" + EOL + EOL +
			"typedef unsigned long long    qword;" + EOL +
			"struct MyStruct { /* this is my structure */" + EOL +
			"    qword myQWord; /* this is my qword */" + EOL +
			"    char myStr[10]; /* this is my string */" + EOL +
			"    double myDouble; /* this is my double */" + EOL +
			"    float * myFloatPointer; /* this is my float pointer */" + EOL + "};" + EOL + EOL;

		assertEquals(expected, actual);
	}

	@Test
	public void testArrayInStructure() throws IOException, CancelledException {
		DataType dt = new FloatDataType();
		Array array = new ArrayDataType(dt, 300, dt.getLength());

		Structure struct = new StructureDataType("MyStruct", 0);
		struct.setDescription("this is my structure");
		struct.add(new QWordDataType(), "myQWord", "this is my qword");
		struct.add(array, "myArray", "this is my array");
		struct.add(new DoubleDataType(), "myDouble", "this is my double");
		struct.add(PointerDataType.getPointer(new FloatDataType(), 4), "myFloatPointer",
			"this is my float pointer");

		dtWriter.write(struct, TaskMonitorAdapter.DUMMY_MONITOR);

		String actual = writer.getBuffer().toString();

		String expected = "typedef struct MyStruct MyStruct, *PMyStruct;" + EOL + EOL +
			"typedef unsigned long long    qword;" + EOL +
			"struct MyStruct { /* this is my structure */" + EOL +
			"    qword myQWord; /* this is my qword */" + EOL +
			"    float myArray[300]; /* this is my array */" + EOL +
			"    double myDouble; /* this is my double */" + EOL +
			"    float * myFloatPointer; /* this is my float pointer */" + EOL + "};" + EOL + EOL;

		assertEquals(expected, actual);
	}

	@Test
	public void testArrayInUnion() throws IOException, CancelledException {
		DataType dt = new FloatDataType();
		Array array = new ArrayDataType(dt, 300, dt.getLength());

		Union union = new UnionDataType("MyUnion");
		union.setDescription("this is my union");
		union.add(new QWordDataType(), "myQWord", "this is my qword");
		union.add(array, "myArray", "this is my array");
		union.add(new DoubleDataType(), "myDouble", "this is my double");
		union.add(PointerDataType.getPointer(new FloatDataType(), 4), "myFloatPointer",
			"this is my float pointer");

		dtWriter.write(union, TaskMonitorAdapter.DUMMY_MONITOR);

		String actual = writer.getBuffer().toString();

		String expected = "typedef union MyUnion MyUnion, *PMyUnion;" + EOL + EOL +
			"typedef unsigned long long    qword;" + EOL +
			"union MyUnion { /* this is my union */" + EOL +
			"    qword myQWord; /* this is my qword */" + EOL +
			"    float myArray[300]; /* this is my array */" + EOL +
			"    double myDouble; /* this is my double */" + EOL +
			"    float * myFloatPointer; /* this is my float pointer */" + EOL + "};" + EOL + EOL;

		assertEquals(expected, actual);
	}

	@Test
	public void testUnionSelfReference() throws IOException, CancelledException {
		Union union = new UnionDataType("MySelfRefUnion");
		union.add(new WordDataType());
		union.add(PointerDataType.getPointer(union, 4));
		union.add(new DoubleDataType());

		dtWriter.write(union, TaskMonitorAdapter.DUMMY_MONITOR);
		String actual = writer.getBuffer().toString();
		String expected = "typedef union MySelfRefUnion MySelfRefUnion, *PMySelfRefUnion;" + EOL +
			EOL + "typedef unsigned short    word;" + EOL + "union MySelfRefUnion {" + EOL +
			"    word field0;" + EOL + "    union MySelfRefUnion * field1;" + EOL +
			"    double field2;" + EOL + "};" + EOL + EOL;

		assertEquals(expected, actual);
	}

	@Test
	public void testPointer() throws IOException, CancelledException {

		// Only base type is written-out - not pointer

		Pointer ptr = PointerDataType.getPointer(null, null);
		dtWriter.write(ptr, TaskMonitorAdapter.DUMMY_MONITOR);
		String actual = writer.getBuffer().toString();
		String expected = "";
		assertEquals(expected, actual);

		ptr = PointerDataType.getPointer(DataType.DEFAULT, null);
		dtWriter.write(ptr, TaskMonitorAdapter.DUMMY_MONITOR);
		actual = writer.getBuffer().toString();
		expected += "typedef unsigned char   undefined;" + EOL + EOL;
		assertEquals(expected, actual);

		TypeDef typedef = new TypedefDataType("BOB", new CharDataType());
		ptr = PointerDataType.getPointer(typedef, null);
		dtWriter.write(ptr, TaskMonitorAdapter.DUMMY_MONITOR);
		actual = writer.getBuffer().toString();
		expected += "typedef char BOB;" + EOL + EOL;
		assertEquals(expected, actual);
	}

}
