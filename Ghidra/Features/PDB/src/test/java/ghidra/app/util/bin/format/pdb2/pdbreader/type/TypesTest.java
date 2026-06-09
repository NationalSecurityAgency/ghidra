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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.BeforeClass;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.RegisterMsSymbol;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

//TODO: not sure if ST variety should get putPadding() or putAlign()

public class TypesTest extends AbstractGenericTest {

	private static AbstractPdb pdb;
	// Important: Must also use this processorIndex value in any tests below that need it to
	//  ensure consistency across the tests.  We are setting it int the pdb here (in the static
	//  assignment block), but we do not know the order that any tests are run, so having the
	//  same value  will ensure consistent results.
	private static Processor processor;
	private static int stringIdMsType1;
	private static int stringIdMsType2;
	private static int substringListMsType1;
	private static int referencedSymbolMsType1;
	private static int methodList16MsType1;
	private static int methodListMsType1;
	private static int vtShapeMsType1;

	@BeforeClass
	public static void setUp() {
		try (DummyPdb700 dummyPdb700 = new DummyPdb700(4096, 4096, 4096, 4096)) {
			pdb = dummyPdb700;
			processor = Processor.I8080;
			pdb.setTargetProcessor(processor);

			PdbByteReader reader;

			// Create records that will be used indirectly
			AbstractMsType type = new DummyMsType(pdb, null);
			AbstractMsType item = new DummyMsType(pdb, null, "Item");

			//=================================
			// typeParser Records
			dummyPdb700.setTypeRecord(4096, type);

			reader = new PdbByteReader(createReferencedSymbolMsTypeBuffer());
			type = TypeParser.parse(pdb, reader);
			referencedSymbolMsType1 = dummyPdb700.addTypeRecord(type);

			reader = new PdbByteReader(createMethodList16MsTypeBuffer());
			type = TypeParser.parse(pdb, reader);
			methodList16MsType1 = dummyPdb700.addTypeRecord(type);

			reader = new PdbByteReader(createMethodListMsTypeBuffer());
			type = TypeParser.parse(pdb, reader);
			methodListMsType1 = dummyPdb700.addTypeRecord(type);

			reader = new PdbByteReader(createVtShapeMsTypeBuffer());
			type = TypeParser.parse(pdb, reader);
			vtShapeMsType1 = dummyPdb700.addTypeRecord(type);

			//=================================
			// IPI Records
			dummyPdb700.setItemRecord(4096, item);

			reader = new PdbByteReader(createStringIdMsTypeBuffer(0, "String1"));
			item = TypeParser.parse(pdb, reader);
			stringIdMsType1 = dummyPdb700.addItemRecord(item);

			reader = new PdbByteReader(createStringIdMsTypeBuffer(0, "String2"));
			item = TypeParser.parse(pdb, reader);
			stringIdMsType2 = dummyPdb700.addItemRecord(item);

			reader = new PdbByteReader(
				createSubstringListMsTypeBuffer(new int[] { stringIdMsType1, stringIdMsType2 }));
			item = TypeParser.parse(pdb, reader);
			substringListMsType1 = dummyPdb700.addItemRecord(item);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of testt: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	@Test
	public void testMsProperty() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(0xffff);
		writer.putUnsignedShort(0x2400);
		writer.putUnsignedShort(0x6c00);
		writer.putUnsignedShort(0xb400);
		PdbByteReader reader = new PdbByteReader(writer.get());
		MsProperty property = new MsProperty(reader);
		String result = property.toString().trim();
		assertEquals("packed ctor ovlops isnested cnested opassign opcast fwdref scoped" +
			" hasuniquename sealed hfa(3) intrinsic interface", result);
		property = new MsProperty(reader);
		result = property.toString().trim();
		assertEquals("sealed intrinsic", result);
		property = new MsProperty(reader);
		result = property.toString().trim();
		assertEquals("sealed hfaFloat intrinsic ref", result);
		property = new MsProperty(reader);
		result = property.toString().trim();
		assertEquals("sealed hfaDouble intrinsic value", result);
	}

	@Test
	public void testFunctionMsAttributes() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		// C++-style return UDT, is constructor, is constructor with vbase class.
		writer.putUnsignedByte(0x07);
		PdbByteReader reader = new PdbByteReader(writer.get());
		FunctionMsAttributes attributes = new FunctionMsAttributes(reader);
		String result = attributes.toString().trim();
		assertEquals("return UDT (C++ style)|instance constructor|instance constructor of a" +
			" class with virtual base", result);
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	// Below is just a small sampling of PrimitiveMsType variations.
	@Test
	public void testPrimitiveMsType0000() {
		AbstractMsType type = pdb.getTypeRecord(RecordNumber.typeRecordNumber(0x0000));
		assertEquals(type instanceof PrimitiveMsType, true);
		String result = type.toString().trim();
		assertEquals("T_NOTYPE", result);
	}

	@Test
	public void testPrimitiveMsType0110() {
		AbstractMsType type = pdb.getTypeRecord(RecordNumber.typeRecordNumber(0x0110));
		assertEquals(type instanceof PrimitiveMsType, true);
		String result = type.toString().trim();
		assertEquals("signed char near*", result);
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	@Test
	public void testUnknownMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(0xffff);
		writer.putBytes(new byte[] { (byte) 0xfe, (byte) 0xfd, (byte) 0xfc }); // dummy data
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof UnknownMsType, true);
		String result = type.toString().trim();
		assertEquals("UNKNOWN_TYPE (0XFFFF): Bytes:\n" + "000000 fe fd fc", result);
	}

	@Test
	public void testBadMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Modifier16MsType.PDB_ID);
		writer.putUnsignedShort(0x07);
		// Incomplete record should cause BadMsType to be created.
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof BadMsType, true);
		String result = type.toString().trim();
		assertEquals("BAD_TYPE: ID=0X0001", result);
	}

	@Test
	public void testModifier16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Modifier16MsType.PDB_ID);
		writer.putUnsignedShort(0x07);
		writer.putUnsignedShort(4096);
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Modifier16MsType, true);
		String result = type.toString().trim();
		assertEquals("const volatile __unaligned DummyMsType", result);
	}

	@Test
	public void testModifierMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ModifierMsType.PDB_ID);
		writer.putInt(4096);
		writer.putUnsignedShort(0x07);
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof ModifierMsType, true);
		String result = type.toString().trim();
		assertEquals("const volatile __unaligned DummyMsType", result);
	}

	@Test
	public void testPointer16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Pointer16MsType.PDB_ID);
		// pointer type = 9 = base(self)
		// pointer mode = 3 = MODE_MEMBER_FUNCTION_POINTER
		int attributes1 = (0x03 << 5) | 0x09;
		int attributes2 = 0x0f;
		writer.putUnsignedByte(attributes1);
		writer.putUnsignedByte(attributes2);
		writer.putUnsignedShort(4096); // Underlying type
		// Conditional stuff next
		writer.putUnsignedShort(4096); // Index of class containing pointer to member
		// member pointer format = 5 = pmf16_nearnvsa
		writer.putUnsignedShort(5);
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Pointer16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType flat ::* <pmf16_nearnvsa>const volatile  DummyMsType", result);
	}

	@Test
	public void testPointerMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(PointerMsType.PDB_ID);
		writer.putInt(4096); // Underlying type
		// pointer type = 9 = base(self)
		// pointer mode = 3 = MODE_MEMBER_FUNCTION_POINTER
		// true for 0:32 pointer
		// true for volatile
		// true for const
		// true for unaligned
		// true for restricted
		// 4 = byte-size of pointer
		// false for MoCOM
		// true for & ref-qualifier
		// false for && ref-qualifier
		long attributes =
			(0 << 22) | (1 << 21) | (0 << 20) | (4 << 14) | (0x1f << 8) | (0x03 << 5) | 0x09;
		writer.putUnsignedInt(attributes);
		// Conditional stuff next
		writer.putInt(4096); // Index of class containing pointer to member
		// member pointer format = 5 = MEMBER_POINTER_FUNCTION_SINGLE_INHERITANCE
		writer.putUnsignedShort(5);
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof PointerMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType flat ::* <pmf16_nearnvsa>const volatile  DummyMsType", result);
	}

	@Test
	public void testArray16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Array16MsType.PDB_ID);
		writer.putUnsignedShort(4096);
		writer.putUnsignedShort(4096);
		writer.putNumeric(new BigInteger("10", 16), 0x8002);
		writer.putByteLengthPrefixedString("name");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Array16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType [16<DummyMsType>]", result);
	}

	@Test
	public void testArrayStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ArrayStMsType.PDB_ID);
		writer.putUnsignedInt(4096);
		writer.putUnsignedInt(4096);
		writer.putNumeric(new BigInteger("10", 16), 0x8002);
		writer.putByteLengthPrefixedString("name");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof ArrayStMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType [16<DummyMsType>]", result);
	}

	@Test
	public void testArrayMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ArrayMsType.PDB_ID);
		writer.putUnsignedInt(4096);
		writer.putUnsignedInt(4096);
		writer.putNumeric(new BigInteger("10", 16), 0x8002);
		writer.putNullTerminatedString("name");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof ArrayMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType [16<DummyMsType>]", result);
	}

	@Test
	public void testStridedArrayMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(StridedArrayMsType.PDB_ID);
		writer.putUnsignedInt(4096);
		writer.putUnsignedInt(4096);
		writer.putNumeric(new BigInteger("10", 16), 0x8002);
		writer.putUnsignedInt(0x0002); // stride value.
		writer.putNullTerminatedString("name");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof StridedArrayMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType [16<DummyMsType>]", result);
	}

	@Test
	public void testClass16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Class16MsType.PDB_ID);
		writer.putUnsignedShort(2); // Count of number of elements in the class.
		writer.putUnsignedShort(4096); // Type index of field descriptor list.
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putUnsignedShort(4096); // If not zero, is type index of derived-from list
		writer.putUnsignedShort(vtShapeMsType1); // Type index of the VtShapeMsType (vshape table).
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of class.
		writer.putByteLengthPrefixedString("ClassName16");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Class16MsType, true);
		String result = type.toString().trim();
		assertEquals("class ClassName16<2,packed ctor>DummyMsType", result);
	}

	@Test
	public void testClassStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ClassStMsType.PDB_ID);
		writer.putUnsignedShort(2); // Count of number of elements in the class.
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putUnsignedInt(4096); // Type index of field descriptor list.
		writer.putUnsignedInt(4096); // If not zero, is type index of derived-from list
		writer.putUnsignedInt(vtShapeMsType1); // Type index of the VtShapeMsType (vshape table).
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of class.
		writer.putByteLengthPrefixedString("ClassNameSt");
		writer.putByteLengthPrefixedString("OtherNameSt");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof ClassStMsType, true);
		String result = type.toString().trim();
		assertEquals("class ClassNameSt<2,packed ctor>DummyMsType", result);
	}

	@Test
	public void testClassMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ClassMsType.PDB_ID);
		writer.putUnsignedShort(2); // Count of number of elements in the class.
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putUnsignedInt(4096); // Type index of field descriptor list.
		writer.putUnsignedInt(4096); // If not zero, is type index of derived-from list
		writer.putUnsignedInt(vtShapeMsType1); // Type index of the VtShapeMsType (vshape table).
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of class.
		writer.putNullTerminatedString("ClassName");
		writer.putNullTerminatedString("OtherName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof ClassMsType, true);
		String result = type.toString().trim();
		assertEquals("class ClassName<2,packed ctor>DummyMsType", result);
	}

	//TODO: Might need adjusting fields of record are understood.
	@Test
	public void testClass19MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Class19MsType.PDB_ID);
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putUnsignedShort(0); // unknown field
		writer.putUnsignedInt(4096); // Type index of field descriptor list.
		writer.putUnsignedInt(4096); // If not zero, is type index of derived-from list
		writer.putUnsignedInt(vtShapeMsType1); // Type index of the VtShapeMsType (vshape table).
		writer.putNumeric(new BigInteger("0", 16), 0x8002); // unk field. Not sure if Numeric
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of class.
		writer.putNullTerminatedString("ClassName");
		writer.putNullTerminatedString("OtherName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Class19MsType, true);
		String result = type.toString().trim();
		assertEquals("class ClassName<packed ctor>DummyMsType", result);
	}

	@Test
	public void testStructure16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Structure16MsType.PDB_ID);
		writer.putUnsignedShort(2); // Count of number of elements in the structure.
		writer.putUnsignedShort(4096); // Type index of field descriptor list.
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putUnsignedShort(4096); // If not zero, is type index of derived-from list
		writer.putUnsignedShort(vtShapeMsType1); // Type index of the VtShapeMsType (vshape table).
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of structure.
		writer.putByteLengthPrefixedString("StructureName16");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Structure16MsType, true);
		String result = type.toString().trim();
		assertEquals("struct StructureName16<2,packed ctor>DummyMsType", result);
	}

	@Test
	public void testStructureStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(StructureStMsType.PDB_ID);
		writer.putUnsignedShort(2); // Count of number of elements in the structure.
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putUnsignedInt(4096); // Type index of field descriptor list.
		writer.putUnsignedInt(4096); // If not zero, is type index of derived-from list
		writer.putUnsignedInt(vtShapeMsType1); // Type index of the VtShapeMsType (vshape table).
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of structure.
		writer.putByteLengthPrefixedString("StructureNameSt");
		writer.putByteLengthPrefixedString("OtherNameSt");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof StructureStMsType, true);
		String result = type.toString().trim();
		assertEquals("struct StructureNameSt<2,packed ctor>DummyMsType", result);
	}

	@Test
	public void testStructureMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(StructureMsType.PDB_ID);
		writer.putUnsignedShort(2); // Count of number of elements in the structure.
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putUnsignedInt(4096); // Type index of field descriptor list.
		writer.putUnsignedInt(4096); // If not zero, is type index of derived-from list
		writer.putUnsignedInt(vtShapeMsType1); // Type index of the VtShapeMsType (vshape table).
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of structure.
		writer.putNullTerminatedString("StructureName");
		writer.putNullTerminatedString("OtherName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof StructureMsType, true);
		String result = type.toString().trim();
		assertEquals("struct StructureName<2,packed ctor>DummyMsType", result);
	}

	//TODO: Might need adjusting fields of record are understood.
	@Test
	public void testStructure19MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Structure19MsType.PDB_ID);
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putUnsignedShort(0); // unknown field
		writer.putUnsignedInt(4096); // Type index of field descriptor list.
		writer.putUnsignedInt(4096); // If not zero, is type index of derived-from list
		writer.putUnsignedInt(vtShapeMsType1); // Type index of the VtShapeMsType (vshape table).
		writer.putNumeric(new BigInteger("0", 16), 0x8002); // unk field. Not sure if Numeric
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of structure.
		writer.putNullTerminatedString("StructureName");
		writer.putNullTerminatedString("OtherName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Structure19MsType, true);
		String result = type.toString().trim();
		assertEquals("struct StructureName<packed ctor>DummyMsType", result);
	}

	@Test
	public void testInterfaceMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(InterfaceMsType.PDB_ID);
		writer.putUnsignedShort(2); // Count of number of elements in the interface.
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putUnsignedInt(4096); // Type index of field descriptor list.
		writer.putUnsignedInt(4096); // If not zero, is type index of derived-from list
		writer.putUnsignedInt(vtShapeMsType1); // Type index of the VtShapeMsType (vshape table).
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of interface.
		writer.putNullTerminatedString("InterfaceName");
		writer.putNullTerminatedString("OtherName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof InterfaceMsType, true);
		String result = type.toString().trim();
		assertEquals("interface InterfaceName<2,packed ctor>DummyMsType", result);
	}

	//TODO: Hypothetical type... will need adjusting as record type is adjusted.
//	@Test
//	public void testInterface19MsType() throws Exception {
//		PdbByteWriter writer = new PdbByteWriter();
//		writer.putUnsignedShort(Interface19MsType.PDB_ID);
//		byte[] propertyBuffer = createMsPropertyBuffer();
//		writer.putBytes(propertyBuffer);
//		writer.putUnsignedShort(0); // unknown field
//		writer.putUnsignedInt(4096); // Type index of field descriptor list.
//		writer.putUnsignedInt(4096); // If not zero, is type index of derived-from list
//		writer.putUnsignedInt(vtShapeMsType1); // Type index of the VtShapeMsType (vshape table).
//		writer.putNumeric(new BigInteger("0", 16), 0x8002); // unk field. Not sure if Numeric
//		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of interface.
//		writer.putNullTerminatedString("InterfaceName");
//		writer.putNullTerminatedString("OtherName");
//		writer.putAlign(2);
//		PdbByteReader reader = new PdbByteReader(writer.get());
//		AbstractMsType type = TypeParser.parse(pdb, reader);
//		assertEquals(type instanceof Interface19MsType, true);
//		String result = type.toString().trim();
//		assertEquals("interface InterfaceName<packed ctor>DummyMsType", result);
//	}

	@Test
	public void testUnion16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Union16MsType.PDB_ID);
		writer.putUnsignedShort(2); // Count of number of elements in the union.
		writer.putUnsignedShort(4096); // Type index of field descriptor list.
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of union.
		writer.putByteLengthPrefixedString("UnionName16");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Union16MsType, true);
		String result = type.toString().trim();
		assertEquals("union UnionName16<2,packed ctor>DummyMsType", result);
	}

	@Test
	public void testUnionStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(UnionStMsType.PDB_ID);
		writer.putUnsignedShort(2); // Count of number of elements in the union.
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putUnsignedInt(4096); // Type index of field descriptor list.
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of union.
		writer.putByteLengthPrefixedString("UnionNameSt");
		writer.putByteLengthPrefixedString("OtherNameSt");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof UnionStMsType, true);
		String result = type.toString().trim();
		assertEquals("union UnionNameSt<2,packed ctor>DummyMsType", result);
	}

	@Test
	public void testUnionMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(UnionMsType.PDB_ID);
		writer.putUnsignedShort(2); // Count of number of elements in the union.
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putUnsignedInt(4096); // Type index of field descriptor list.
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of union.
		writer.putNullTerminatedString("UnionName");
		writer.putNullTerminatedString("OtherName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof UnionMsType, true);
		String result = type.toString().trim();
		assertEquals("union UnionName<2,packed ctor>DummyMsType", result);
	}

	//TODO: Hypothetical type... will need adjusting as record type is adjusted.
//	@Test
//	public void testUnion19MsType() throws Exception {
//		PdbByteWriter writer = new PdbByteWriter();
//		writer.putUnsignedShort(Union19MsType.PDB_ID);
//		byte[] propertyBuffer = createMsPropertyBuffer();
//		writer.putBytes(propertyBuffer);
//		writer.putUnsignedShort(0); // unknown field
//		writer.putUnsignedInt(4096); // Type index of field descriptor list.
//		writer.putNumeric(new BigInteger("0", 16), 0x8002); // unk field. Not sure if Numeric
//		writer.putNumeric(new BigInteger("10", 16), 0x8002); // size of union.
//		writer.putNullTerminatedString("UnionName");
//		writer.putNullTerminatedString("OtherName");
//		writer.putAlign(2);
//		PdbByteReader reader = new PdbByteReader(writer.get());
//		AbstractMsType type = TypeParser.parse(pdb, reader);
//		assertEquals(type instanceof Union19MsType, true);
//		String result = type.toString().trim();
//		assertEquals("union UnionName<packed ctor>DummyMsType", result);
//	}

	@Test
	public void testEnum16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Enum16MsType.PDB_ID);
		writer.putUnsignedShort(2); // Count of number of elements in the class.
		writer.putUnsignedShort(4096); // Underlying type index.
		writer.putUnsignedShort(4096); // Type index of field descriptor list.
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putByteLengthPrefixedString("EnumName16");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Enum16MsType, true);
		String result = type.toString().trim();
		assertEquals("enum EnumName16<2,DummyMsType,packed ctor>DummyMsType", result);
	}

	@Test
	public void testEnumStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(EnumStMsType.PDB_ID);
		writer.putUnsignedShort(2); // Count of number of elements in the class.
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putUnsignedInt(4096); // Underlying type index.
		writer.putUnsignedInt(4096); // Type index of field descriptor list.
		writer.putByteLengthPrefixedString("EnumNameSt");
		writer.putByteLengthPrefixedString("OtherNameSt");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof EnumStMsType, true);
		String result = type.toString().trim();
		assertEquals("enum EnumNameSt<2,DummyMsType,packed ctor>DummyMsType", result);
	}

	@Test
	public void testEnumMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(EnumMsType.PDB_ID);
		writer.putUnsignedShort(2); // Count of number of elements in the class.
		byte[] propertyBuffer = createMsPropertyBuffer();
		writer.putBytes(propertyBuffer);
		writer.putUnsignedInt(4096); // Underlying type index.
		writer.putUnsignedInt(4096); // Type index of field descriptor list.
		writer.putNullTerminatedString("EnumName");
		writer.putNullTerminatedString("OtherName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof EnumMsType, true);
		String result = type.toString().trim();
		assertEquals("enum EnumName<2,DummyMsType,packed ctor>DummyMsType", result);
	}

	//TODO: Hypothetical type... will need adjusting as record type is adjusted.
//	@Test
//	public void testEnum19MsType() throws Exception {
//		PdbByteWriter writer = new PdbByteWriter();
//		writer.putUnsignedShort(Enum19MsType.PDB_ID);
//		byte[] propertyBuffer = createMsPropertyBuffer();
//		writer.putBytes(propertyBuffer);
//		writer.putUnsignedShort(0); // unknown field
//		writer.putUnsignedInt(4096); // Underlying type index.
//		writer.putUnsignedInt(4096); // Type index of field descriptor list.
//		writer.putNullTerminatedString("EnumName");
//		writer.putNullTerminatedString("OtherName");
//		writer.putAlign(2);
//		PdbByteReader reader = new PdbByteReader(writer.get());
//		AbstractMsType type = TypeParser.parse(pdb, reader);
//		assertEquals(type instanceof Enum19MsType, true);
//		String result = type.toString().trim();
//		assertEquals("enum EnumName<DummyMsType,packed ctor>DummyMsType", result);
//	}

	@Test
	public void testProcedure16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Procedure16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // Return type index.
		writer.putUnsignedByte(0x01); // Calling convention.
		byte[] attributesBuffer = createFunctionMsAttributesBuffer();
		writer.putBytes(attributesBuffer);
		writer.putUnsignedShort(2); // Number of parameters.
		writer.putUnsignedShort(4096); // Type index arguments list.
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Procedure16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType DummyMsType", result);
	}

	@Test
	public void testProcedureMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ProcedureMsType.PDB_ID);
		writer.putUnsignedInt(4096); // Return type index.
		writer.putUnsignedByte(0x01); // Calling convention.
		byte[] attributesBuffer = createFunctionMsAttributesBuffer();
		writer.putBytes(attributesBuffer);
		writer.putUnsignedShort(2); // Number of parameters.
		writer.putUnsignedInt(4096); // Type index of arguments list.
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof ProcedureMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType DummyMsType", result);
	}

	@Test
	public void testMemberFunction16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(MemberFunction16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // Return type index.
		writer.putUnsignedShort(4096); // Class type index.
		writer.putUnsignedShort(4096); // "this" type index.
		writer.putUnsignedByte(0x01); // Calling convention.
		byte[] attributesBuffer = createFunctionMsAttributesBuffer();
		writer.putBytes(attributesBuffer);
		writer.putUnsignedShort(2); // Number of parameters.
		writer.putUnsignedShort(4096); // Type index arguments list.
		writer.putInt(0x08); // This adjuster.
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof MemberFunction16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType DummyMsType::DummyMsType<DummyMsType this,8,2,return UDT" +
			" (C++ style)|instance constructor|instance constructor of a class with" +
			" virtual base>", result);
	}

	@Test
	public void testMemberFunctionMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(MemberFunctionMsType.PDB_ID);
		writer.putUnsignedInt(4096); // Return type index.
		writer.putUnsignedInt(4096); // Class type index.
		writer.putUnsignedInt(4096); // "this" type index.
		writer.putUnsignedByte(0x01); // Calling convention.
		byte[] attributesBuffer = createFunctionMsAttributesBuffer();
		writer.putBytes(attributesBuffer);
		writer.putUnsignedShort(2); // Number of parameters.
		writer.putUnsignedInt(4096); // Type index of arguments list.
		writer.putInt(0x08); // This adjuster.
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof MemberFunctionMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType DummyMsType::DummyMsType<DummyMsType this,8,2,return UDT" +
			" (C++ style)|instance constructor|instance constructor of a class with" +
			" virtual base>", result);
	}

	@Test
	public void testVtShapeMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		byte[] vtShapeMsTypeBytes = createVtShapeMsTypeBuffer();
		writer.putBytes(vtShapeMsTypeBytes);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof VtShapeMsType, true);
		String result = type.toString().trim();
		assertEquals("vtshape: {near,far,thin,outer,meta,near32,far32}", result);
	}

	@Test
	public void testVirtualFunctionTableMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VirtualFunctionTableMsType.PDB_ID);
		writer.putUnsignedInt(4096); // class/struct owner of vftable
		writer.putUnsignedInt(4096); // vftable from which this vftable is derived.
		writer.putUnsignedInt(8); // offset of vfptr to this table, relative to object layout
		PdbByteWriter namesWriter = new PdbByteWriter();
		namesWriter.putNullTerminatedString("tableName");
		namesWriter.putNullTerminatedString("methodName1");
		namesWriter.putNullTerminatedString("methodName2");
		writer.putAlign(2);
		byte[] namesBytes = namesWriter.get();
		writer.putUnsignedInt(namesBytes.length); // length of names array
		writer.putBytes(namesBytes);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof VirtualFunctionTableMsType, true);
		String result = type.toString().trim();
		assertEquals("VFTable for [DummyMsType<vfptr_offset=8> : DummyMsType] tableName:" +
			" {methodName1,methodName2}", result);
	}

	@Test
	public void testCobol016MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Cobol016MsType.PDB_ID);
		writer.putUnsignedShort(4096); // Parent type index.
		// TODO: This is made up data.  API and examples are unknown.
		writer.putBytes(new byte[] { 0x03, 0x02, 0x01, 0x00 });
		//writer.putAlign(2); // TODO: Not sure
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Cobol016MsType, true);
		String result = type.toString().trim();
		assertEquals(
			"Cobol0MsType\n" + "  parent type index: DummyMsType\n" + "  additional data length: 4",
			result);
	}

	@Test
	public void testCobol0MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Cobol0MsType.PDB_ID);
		writer.putUnsignedInt(4096); // Parent type index.
		// TODO: This is made up data.  API and examples are unknown.
		writer.putBytes(new byte[] { 0x03, 0x02, 0x01, 0x00 });
		writer.putAlign(2); // TODO: Not sure
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Cobol0MsType, true);
		String result = type.toString().trim();
		assertEquals(
			"Cobol0MsType\n" + "  parent type index: DummyMsType\n" + "  additional data length: 4",
			result);
	}

	@Test
	public void testCobol1MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Cobol1MsType.PDB_ID);
		// TODO: This is made up data.  API and examples are unknown.
		writer.putBytes(new byte[] { 0x03, 0x02, 0x01, 0x00 });
		writer.putAlign(2); // TODO: Not sure
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Cobol1MsType, true);
		String result = type.toString().trim();
		assertEquals("Cobol1MsType\n" + "  additional data length: 4", result);
	}

	@Test
	public void testBasicArray16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(BasicArray16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // Parent type index.
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof BasicArray16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType[]", result);
	}

	@Test
	public void testBasicArrayMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(BasicArrayMsType.PDB_ID);
		writer.putUnsignedInt(4096); // Parent type index.
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof BasicArrayMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType[]", result);
	}

	@Test
	public void testLabelMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(LabelMsType.PDB_ID);
		writer.putUnsignedShort(4); // 0 = NEAR; 4 = FAR addressing mode.
		writer.putAlign(2); // TODO: Not sure
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof LabelMsType, true);
		String result = type.toString().trim();
		assertEquals("<<LabelMsType far>>", result);
	}

	@Test
	public void testNullMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(NullMsType.PDB_ID);
		writer.putAlign(2); // TODO: Not sure
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof NullMsType, true);
		String result = type.toString().trim();
		assertEquals("<<NullMsType>>", result);
	}

	@Test
	public void testNotTranMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(NotTranMsType.PDB_ID);
		writer.putAlign(2); // TODO: Not sure
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof NotTranMsType, true);
		String result = type.toString().trim();
		assertEquals("<<NotTranMsType>>", result);
	}

	@Test
	public void testDimensionedArray16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DimensionedArray16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // Underlying type index.
		writer.putUnsignedShort(116); // Dimension information.
		writer.putByteLengthPrefixedString("name");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DimensionedArray16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType [<int>]", result);
	}

	@Test
	public void testDimensionedArrayStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DimensionedArrayStMsType.PDB_ID);
		writer.putUnsignedInt(4096); // Underlying type index.
		writer.putUnsignedInt(116); // Dimension information.
		writer.putByteLengthPrefixedString("name");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DimensionedArrayStMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType [<int>]", result);
	}

	@Test
	public void testDimensionedArrayMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DimensionedArrayMsType.PDB_ID);
		writer.putUnsignedInt(4096); // Underlying type index.
		writer.putUnsignedInt(116); // Dimension information.
		writer.putNullTerminatedString("name");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DimensionedArrayMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType [<int>]", result);
	}

	@Test
	public void testVirtualFunctionTablePath16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VirtualFunctionTablePath16MsType.PDB_ID);
		writer.putUnsignedShort(2); // count
		writer.putUnsignedShort(4096); // a type index
		writer.putUnsignedShort(4096); // a type index
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof VirtualFunctionTablePath16MsType, true);
		String result = type.toString().trim();
		assertEquals("VFTPath: count=2\n" + "   base[0]=DummyMsType\n" + "   base[1]=DummyMsType",
			result);
	}

	@Test
	public void testVirtualFunctionTablePathMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VirtualFunctionTablePathMsType.PDB_ID);
		writer.putInt(2); // count
		writer.putInt(4096); // a type index
		writer.putInt(4096); // a type index
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof VirtualFunctionTablePathMsType, true);
		String result = type.toString().trim();
		assertEquals("VFTPath: count=2\n" + "   base[0]=DummyMsType\n" + "   base[1]=DummyMsType",
			result);
	}

	@Test
	public void testPrecompiledType16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(PrecompiledType16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // a "start" type index
		writer.putUnsignedShort(2); // count
		writer.putUnsignedInt(0xfedcba98L); // made-up signature
		writer.putByteLengthPrefixedString("filename");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof PrecompiledType16MsType, true);
		String result = type.toString().trim();
		assertEquals(
			"Precompiled: signature=0XFEDCBA98, name=filename, start=DummyMsType," + " count=2",
			result);
	}

	@Test
	public void testPrecompiledTypeStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(PrecompiledTypeStMsType.PDB_ID);
		writer.putInt(4096); // a "start" type index
		writer.putInt(2); // count
		writer.putUnsignedInt(0xfedcba98L); // made-up signature
		writer.putByteLengthPrefixedString("filename");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof PrecompiledTypeStMsType, true);
		String result = type.toString().trim();
		assertEquals(
			"Precompiled: signature=0XFEDCBA98, name=filename, start=DummyMsType," + " count=2",
			result);
	}

	@Test
	public void testPrecompiledTypeMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(PrecompiledTypeMsType.PDB_ID);
		writer.putInt(4096); // a "start" type index
		writer.putInt(2); // count
		writer.putUnsignedInt(0xfedcba98L); // made-up signature
		writer.putNullTerminatedString("filename");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof PrecompiledTypeMsType, true);
		String result = type.toString().trim();
		assertEquals(
			"Precompiled: signature=0XFEDCBA98, name=filename, start=DummyMsType," + " count=2",
			result);
	}

	@Test
	public void testEndPrecompiledTypeMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(EndPrecompiledTypeMsType.PDB_ID);
		writer.putUnsignedInt(0xfedcba98L); // made-up signature
		writer.putAlign(2); // TODO: Not sure
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof EndPrecompiledTypeMsType, true);
		String result = type.toString().trim();
		assertEquals("EndPrecompiled: signature=0XFEDCBA98", result);
	}

	@Test
	public void testOemDefinableString16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(OemDefinableString16MsType.PDB_ID);
		writer.putUnsignedShort(8192); // MSFT-assigned OEM identifier.
		writer.putUnsignedShort(8193); // OEM-assigned identifier.
		writer.putUnsignedShort(2); // count
		writer.putUnsignedShort(4096); // type index
		writer.putUnsignedShort(4096); // type index
		// TODO: what is OEM-defined data that should follow?
		writer.putBytes(new byte[] { 0x03, 0x02, 0x01, 0x00 });
		//writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof OemDefinableString16MsType, true);
		String result = type.toString().trim();
		assertEquals("OEM Definable String\n" + "  MSFT-assigned OEM Identifier: 8192\n" +
			"  OEM-assigned Identifier: 8193\n" + "  count: 2\n" +
			"    recordNumber[0]: 0x00001000\n" + "    recordNumber[1]: 0x00001000\n" +
			"  additional data length: 4", result);
	}

	@Test
	public void testOemDefinableStringMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(OemDefinableStringMsType.PDB_ID);
		writer.putUnsignedShort(8192); // MSFT-assigned OEM identifier.
		writer.putUnsignedShort(8193); // OEM-assigned identifier.
		writer.putInt(2); // count
		writer.putInt(4096); // type index
		writer.putInt(4096); // type index
		// TODO: what is OEM-defined data that should follow?
		writer.putBytes(new byte[] { 0x03, 0x02, 0x01, 0x00 });
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof OemDefinableStringMsType, true);
		String result = type.toString().trim();
		assertEquals("OEM Definable String\n" + "  MSFT-assigned OEM Identifier: 8192\n" +
			"  OEM-assigned Identifier: 8193\n" + "  count: 2\n" +
			"    recordNumber[0]: 0x00001000\n" + "    recordNumber[1]: 0x00001000\n" +
			"  additional data length: 4", result);
	}

	@Test
	public void testOemDefinableString2MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(OemDefinableString2MsType.PDB_ID);
		writer.putGUID(0x0c0d0e0f, (short) 0x0a0b, (short) 0x0809,
			new byte[] { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 });
		writer.putInt(2); // count
		writer.putInt(4096); // type index
		writer.putInt(4096); // type index
		// TODO: what is OEM-defined data that should follow?
		writer.putBytes(new byte[] { 0x03, 0x02, 0x01, 0x00 });
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof OemDefinableString2MsType, true);
		String result = type.toString().trim();
		assertEquals("OEM Definable String 2\n" + "  GUID: 0c0d0e0f-0a0b-0809-0706-050403020100\n" +
			"  count: 2\n" + "    recordNumber[0]: 0x00001000\n" +
			"    recordNumber[1]: 0x00001000\n" + "  additional data length: 4", result);
	}

	@Test
	public void testTypeServerStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(TypeServerStMsType.PDB_ID);
		writer.putUnsignedInt(0xfedcba98); // signature
		writer.putUnsignedInt(1); // age
		writer.putByteLengthPrefixedString("serverSt");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof TypeServerStMsType, true);
		String result = type.toString().trim();
		assertEquals("<<TypeServerStMsType serverSt 0xfedcba98 1>>", result);
	}

	@Test
	public void testTypeServerMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(TypeServerMsType.PDB_ID);
		writer.putUnsignedInt(0xfedcba98); // signature
		writer.putUnsignedInt(1); // age
		writer.putNullTerminatedString("server");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof TypeServerMsType, true);
		String result = type.toString().trim();
		assertEquals("<<TypeServerMsType server 0xfedcba98 1>>", result);
	}

	@Test
	public void testTypeServer2MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(TypeServer2MsType.PDB_ID);
		writer.putGUID(0x0c0d0e0f, (short) 0x0a0b, (short) 0x0809,
			new byte[] { 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 });
		writer.putUnsignedInt(1); // age
		writer.putNullTerminatedString("server");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof TypeServer2MsType, true);
		String result = type.toString().trim();
		assertEquals("<<TypeServer2MsType server 0c0d0e0f-0a0b-0809-0706-050403020100 1>>", result);
	}

	@Test
	public void testSkip16() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Skip16MsType.PDB_ID);
		writer.putUnsignedShort(8192); // next "valid" index
		// pad bytes (not sure how many to put--probably normal align.
		writer.putBytes(new byte[] { (byte) 0xf1, (byte) 0xf2 });
		//writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Skip16MsType, true);
		String result = type.toString().trim();
		assertEquals("Skip Record, nextValidTypeIndex = 0x2000, Length = 0x2", result);
	}

	@Test
	public void testSkipMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(SkipMsType.PDB_ID);
		writer.putInt(8192);  // next "valid" index
		// pad bytes (not sure how many to put--probably normal align (zero here?).
		writer.putBytes(new byte[] { 0x03, 0x02, 0x01, 0x00 });
		//writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof SkipMsType, true);
		String result = type.toString().trim();
		assertEquals("Skip Record, nextValidTypeIndex = 0x2000, Length = 0x4", result);
	}

	@Test
	public void testArgumentsList16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ArgumentsList16MsType.PDB_ID);
		writer.putUnsignedShort(2); // Number of arguments.
		writer.putUnsignedShort(4096); // Type index of argument.
		writer.putUnsignedShort(4096); // Type index of argument.
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof ArgumentsList16MsType, true);
		String result = type.toString().trim();
		assertEquals("(DummyMsType, DummyMsType)", result);
	}

	@Test
	public void testArgumentsListMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ArgumentsListMsType.PDB_ID);
		writer.putUnsignedInt(2); // Number of arguments.
		writer.putUnsignedInt(4096); // Type index of argument.
		writer.putUnsignedInt(4096); // Type index of argument.
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof ArgumentsListMsType, true);
		String result = type.toString().trim();
		assertEquals("(DummyMsType, DummyMsType)", result);
	}

	@Test
	public void testSubstringListMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(SubstringListMsType.PDB_ID);
		writer.putUnsignedInt(2); // Number of elements.
		writer.putUnsignedInt(stringIdMsType1); // Type index of element.
		writer.putUnsignedInt(stringIdMsType2); // Type index of element.
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof SubstringListMsType, true);
		String result = type.toString().trim();
		assertEquals("String1String2", result);
	}

	@Test
	public void testStringIdMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(StringIdMsType.PDB_ID);
		// Type index of SubStringListMsType (or 0 if not needed)
		writer.putUnsignedInt(substringListMsType1);
		writer.putNullTerminatedString("TailOfString");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof StringIdMsType, true);
		String result = type.toString().trim();
		assertEquals("String1String2TailOfString", result);
	}

	@Test
	public void testDefaultArguments16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DefaultArguments16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // type index of expression type.
		writer.putByteLengthPrefixedString("expression");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DefaultArguments16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType expression", result);
	}

	@Test
	public void testDefaultArgumentsStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DefaultArgumentsStMsType.PDB_ID);
		writer.putUnsignedInt(4096); // type index of expression type.
		writer.putByteLengthPrefixedString("expression");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DefaultArgumentsStMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType expression", result);
	}

	@Test
	public void testDefaultArgumentsMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DefaultArgumentsMsType.PDB_ID);
		writer.putUnsignedInt(4096); // type index of expression type.
		writer.putNullTerminatedString("expression");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DefaultArgumentsMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType expression", result);
	}

	@Test
	public void testListMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ListMsType.PDB_ID);
		writer.putUnsignedByte(0x41);
		//writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof ListMsType, true);
		String result = type.toString().trim();
		assertEquals("<<ListMsType dataLength=1>>", result);
	}

	@Test
	public void testFieldList16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(FieldList16MsType.PDB_ID);
		byte[] baseClass16MsTypeBytes = createBaseClass16MsTypeBuffer();
		byte[] member16MsTypeBytes = createMember16MsTypeBuffer();
		writer.putBytes(baseClass16MsTypeBytes);
		writer.putPadding(0); // Records in FieldList align on their own basis
		writer.putBytes(baseClass16MsTypeBytes);
		writer.putPadding(0); // Records in FieldList align on their own basis
		writer.putBytes(member16MsTypeBytes);
		writer.putPadding(0); // Records in FieldList align on their own basis
		writer.putBytes(member16MsTypeBytes);
		writer.putPadding(0); // Records in FieldList align on their own basis
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof FieldList16MsType, true);
		String result = type.toString().trim();
		assertEquals(": public static<pseudo, noinherit, noconstruct>:DummyMsType<@16>, public" +
			" static<pseudo, noinherit, noconstruct>:DummyMsType<@16> {public static<pseudo," +
			" noinherit, noconstruct>: DummyMsType memberName<@16>,public static<pseudo," +
			" noinherit, noconstruct>: DummyMsType memberName<@16>}", result);
	}

	@Test
	public void testFieldListMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(FieldListMsType.PDB_ID);
		byte[] baseClassMsTypeBytes = createBaseClassMsTypeBuffer();
		byte[] memberMsTypeBytes = createMemberMsTypeBuffer();
		writer.putBytes(baseClassMsTypeBytes);
		writer.putPadding(0); // Records in FieldList align on their own basis
		writer.putBytes(baseClassMsTypeBytes);
		writer.putPadding(0); // Records in FieldList align on their own basis
		writer.putBytes(memberMsTypeBytes);
		writer.putPadding(0); // Records in FieldList align on their own basis
		writer.putBytes(memberMsTypeBytes);
		writer.putPadding(0); // Records in FieldList align on their own basis
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof FieldListMsType, true);
		String result = type.toString().trim();
		assertEquals(": public static<pseudo, noinherit, noconstruct>:DummyMsType<@16>, public" +
			" static<pseudo, noinherit, noconstruct>:DummyMsType<@16> {public static<pseudo," +
			" noinherit, noconstruct>: DummyMsType memberName<@16>,public static<pseudo," +
			" noinherit, noconstruct>: DummyMsType memberName<@16>}", result);
	}

	@Test
	public void testDerivedClassList16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DerivedClassList16MsType.PDB_ID);
		writer.putUnsignedShort(2); // count
		writer.putUnsignedShort(4096); // type index
		writer.putUnsignedShort(4096); // type index
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DerivedClassList16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType, DummyMsType", result);
	}

	@Test
	public void testDerivedClassListMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DerivedClassListMsType.PDB_ID);
		writer.putUnsignedInt(2); // count
		writer.putUnsignedInt(4096); // type index
		writer.putUnsignedInt(4096); // type index
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DerivedClassListMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType, DummyMsType", result);
	}

	@Test
	public void testBitfield16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Bitfield16MsType.PDB_ID);
		writer.putUnsignedByte(2); // length
		writer.putUnsignedByte(2); // position
		writer.putUnsignedShort(4096); // type index
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Bitfield16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType : 2 <@2>", result);
	}

	@Test
	public void testBitfieldMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(BitfieldMsType.PDB_ID);
		writer.putUnsignedInt(4096); // type index
		writer.putUnsignedByte(2); // length
		writer.putUnsignedByte(2); // position
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof BitfieldMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType : 2 <@2>", result);
	}

	@Test
	public void testMethodList16MsType() throws Exception {
		PdbByteReader reader = new PdbByteReader(createMethodList16MsTypeBuffer());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof MethodList16MsType, true);
		String result = type.toString().trim();
		assertEquals("{<public static<pseudo, noinherit, noconstruct>: DummyMsType>,<public" +
			" <intro><pseudo, noinherit, noconstruct>: DummyMsType,8>}", result);

	}

	@Test
	public void testMethodListMsType() throws Exception {
		PdbByteReader reader = new PdbByteReader(createMethodListMsTypeBuffer());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof MethodListMsType, true);
		String result = type.toString().trim();
		assertEquals("{<public static<pseudo, noinherit, noconstruct>: DummyMsType>,<public" +
			" <intro><pseudo, noinherit, noconstruct>: DummyMsType,8>}", result);
	}

	@Test
	public void testDimensionedArrayConstBoundsUpper16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DimensionedArrayConstBoundsUpper16MsType.PDB_ID);
		writer.putUnsignedShort(2); // rank
		writer.putUnsignedShort(4096); // type index
		// dimData is dummy data for now.  TODO: figure out and fix.
		writer.putBytes(new byte[] { 0x02, 0x03 });
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DimensionedArrayConstBoundsUpper16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType[0:2][0:3]", result);

	}

	@Test
	public void testDimensionedArrayConstBoundsUpperMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DimensionedArrayConstBoundsUpperMsType.PDB_ID);
		writer.putInt(4096); // type index
		writer.putUnsignedShort(2); // rank
		// dimData is dummy data for now.  TODO: figure out and fix.
		writer.putBytes(new byte[] { 0x02, 0x03 });
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DimensionedArrayConstBoundsUpperMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType[0:2][0:3]", result);
	}

	@Test
	public void testDimensionedArrayConstBoundsLowerUpper16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DimensionedArrayConstBoundsLowerUpper16MsType.PDB_ID);
		writer.putUnsignedShort(2); // rank
		writer.putUnsignedShort(4096); // type index
		// dimData is dummy data for now.  TODO: figure out and fix.
		writer.putBytes(new byte[] { 0x00, 0x01, 0x02, 0x03 });
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DimensionedArrayConstBoundsLowerUpper16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType[0:1][2:3]", result);

	}

	@Test
	public void testDimensionedArrayConstBoundsLowerUpperMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DimensionedArrayConstBoundsLowerUpperMsType.PDB_ID);
		writer.putInt(4096); // type index
		writer.putUnsignedShort(2); // rank
		// dimData is dummy data for now.  TODO: figure out and fix.
		writer.putBytes(new byte[] { 0x00, 0x01, 0x02, 0x03 });
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DimensionedArrayConstBoundsLowerUpperMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType[0:1][2:3]", result);
	}

	@Test
	public void testDimensionedArrayVarBoundsUpper16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DimensionedArrayVarBoundsUpper16MsType.PDB_ID);
		writer.putUnsignedShort(2); // rank
		writer.putUnsignedShort(4096); // type index
		writer.putUnsignedShort(referencedSymbolMsType1); // dim 0 upper type
		writer.putUnsignedShort(3); // dim 1 upper primitive type "void"
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DimensionedArrayVarBoundsUpper16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType[0:REGISTER: al, Type: DummyMsType, registerSymbolName][0:void]",
			result);
	}

	@Test
	public void testDimensionedArrayVarBoundsUpperMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DimensionedArrayVarBoundsUpperMsType.PDB_ID);
		writer.putInt(2); // rank
		writer.putInt(4096); // type index
		writer.putInt(referencedSymbolMsType1); // dim 0 upper type
		writer.putInt(3); // dim 1 upper primitive type "void"
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DimensionedArrayVarBoundsUpperMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType[0:REGISTER: al, Type: DummyMsType, registerSymbolName][0:void]",
			result);
	}

	@Test
	public void testDimensionedArrayVarBoundsLowerUpper16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DimensionedArrayVarBoundsLowerUpper16MsType.PDB_ID);
		writer.putUnsignedShort(2); // rank
		writer.putUnsignedShort(4096); // type index
		writer.putUnsignedShort(referencedSymbolMsType1); // dim 0 lower type
		writer.putUnsignedShort(3);  // dim 0 upper primitive type "void"
		writer.putUnsignedShort(3);  // dim 1 lower primitive type "void"
		writer.putUnsignedShort(referencedSymbolMsType1);  // dim 1 upper type
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DimensionedArrayVarBoundsLowerUpper16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType[REGISTER: al, Type: DummyMsType, registerSymbolName:void]" +
			"[void:REGISTER: al, Type: DummyMsType, registerSymbolName]", result);
	}

	@Test
	public void testDimensionedArrayVarBoundsLowerUpperMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(DimensionedArrayVarBoundsLowerUpperMsType.PDB_ID);
		writer.putInt(2); // rank
		writer.putInt(4096); // type index
		writer.putInt(referencedSymbolMsType1); // dim 0 lower type
		writer.putInt(3);  // dim 0 upper primitive type "void"
		writer.putInt(3);  // dim 1 lower primitive type "void"
		writer.putInt(referencedSymbolMsType1);  // dim 1 upper type
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof DimensionedArrayVarBoundsLowerUpperMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType[REGISTER: al, Type: DummyMsType, registerSymbolName:void]" +
			"[void:REGISTER: al, Type: DummyMsType, registerSymbolName]", result);
	}

	@Test
	public void testReferencedSymbolMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		byte[] symbolBytes = createReferencedSymbolMsTypeBuffer();
		writer.putBytes(symbolBytes);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof ReferencedSymbolMsType, true);
		String result = type.toString().trim();
		assertEquals("REGISTER: al, Type: DummyMsType, registerSymbolName", result);
	}

	@Test
	public void testBaseClass16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		byte[] symbolBytes = createBaseClass16MsTypeBuffer();
		writer.putBytes(symbolBytes);
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof BaseClass16MsType, true);
		String result = type.toString().trim();
		assertEquals("public static<pseudo, noinherit, noconstruct>:DummyMsType<@16>", result);
	}

	@Test
	public void testBaseClassMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		byte[] symbolBytes = createBaseClassMsTypeBuffer();
		writer.putBytes(symbolBytes);
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof BaseClassMsType, true);
		String result = type.toString().trim();
		assertEquals("public static<pseudo, noinherit, noconstruct>:DummyMsType<@16>", result);
	}

	@Test
	public void testBaseInterfaceMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(BaseInterfaceMsType.PDB_ID);
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(4096); // type index of base class
		writer.putNumeric(new BigInteger("10", 16), 0x8002); //offset of base class within class
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof BaseInterfaceMsType, true);
		String result = type.toString().trim();
		assertEquals("public static<pseudo, noinherit, noconstruct>:DummyMsType<@16>", result);
	}

	@Test
	public void testVirtualBaseClass16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VirtualBaseClass16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // type index of direct virtual base class
		writer.putUnsignedShort(4096); // type index of virtual base class
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		// Offset of virtual base pointer from address point
		writer.putNumeric(new BigInteger("10", 16), 0x8002);
		// Offset of virtual base from vbtable.
		writer.putNumeric(new BigInteger("10", 16), 0x8002);
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof VirtualBaseClass16MsType, true);
		String result = type.toString().trim();
		assertEquals("public static<pseudo, noinherit, noconstruct>: < DummyMsType vbp;" +
			" offVbp=16; offVbte=16; >", result);
	}

	@Test
	public void testVirtualBaseClassMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VirtualBaseClassMsType.PDB_ID);
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(4096); // type index of direct virtual base class
		writer.putInt(4096); // type index of virtual base class
		// Offset of virtual base pointer from address point
		writer.putNumeric(new BigInteger("10", 16), 0x8002);
		// Offset of virtual base from vbtable.
		writer.putNumeric(new BigInteger("10", 16), 0x8002);
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof VirtualBaseClassMsType, true);
		String result = type.toString().trim();
		assertEquals("public static<pseudo, noinherit, noconstruct>: < DummyMsType vbp;" +
			" offVbp=16; offVbte=16; >", result);
	}

	@Test
	public void testIndirectVirtualBaseClass16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(IndirectVirtualBaseClass16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // type index of direct virtual base class
		writer.putUnsignedShort(4096); // type index of virtual base class
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		// Offset of virtual base pointer from address point
		writer.putNumeric(new BigInteger("10", 16), 0x8002);
		// Offset of virtual base from vbtable.
		writer.putNumeric(new BigInteger("10", 16), 0x8002);
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof IndirectVirtualBaseClass16MsType, true);
		String result = type.toString().trim();
		assertEquals("<indirect public static<pseudo, noinherit, noconstruct>: DummyMsType vbp;" +
			" offVbp=16; offVbte=16; >", result);
	}

	@Test
	public void testIndirectVirtualBaseClassMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(IndirectVirtualBaseClassMsType.PDB_ID);
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(4096); // type index of direct virtual base class
		writer.putInt(4096); // type index of virtual base class
		// Offset of virtual base pointer from address point
		writer.putNumeric(new BigInteger("10", 16), 0x8002);
		// Offset of virtual base from vbtable.
		writer.putNumeric(new BigInteger("10", 16), 0x8002);
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof IndirectVirtualBaseClassMsType, true);
		String result = type.toString().trim();
		assertEquals("<indirect public static<pseudo, noinherit, noconstruct>: DummyMsType vbp;" +
			" offVbp=16; offVbte=16; >", result);
	}

	@Test
	public void testEnumerateStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(EnumerateStMsType.PDB_ID);
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // Value
		writer.putByteLengthPrefixedString("enumerateName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof EnumerateStMsType, true);
		String result = type.toString().trim();
		assertEquals("public static<pseudo, noinherit, noconstruct>: enumerateName=16", result);
	}

	@Test
	public void testEnumerateMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(EnumerateMsType.PDB_ID);
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // Value
		writer.putNullTerminatedString("enumerateName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof EnumerateMsType, true);
		String result = type.toString().trim();
		assertEquals("public static<pseudo, noinherit, noconstruct>: enumerateName=16", result);
	}

	@Test
	public void testFriendFunction16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(FriendFunction16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // type index of friend function.
		writer.putByteLengthPrefixedString("friendFunctionName");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof FriendFunction16MsType, true);
		String result = type.toString().trim();
		// TODO: probably need a type other than 4096... need something that emits like a function.
		assertEquals("friend: DummyMsType friendFunctionName", result);
	}

	@Test
	public void testFriendFunctionStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(FriendFunctionStMsType.PDB_ID);
		writer.putBytes(new byte[] { 0x00, 0x00 }); // padding
		writer.putInt(4096); // type index of friend function.
		writer.putByteLengthPrefixedString("friendFunctionName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof FriendFunctionStMsType, true);
		String result = type.toString().trim();
		// TODO: probably need a type other than 4096... need something that emits like a function.
		assertEquals("friend: DummyMsType friendFunctionName", result);
	}

	@Test
	public void testFriendFunctionMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(FriendFunctionMsType.PDB_ID);
		writer.putBytes(new byte[] { 0x00, 0x00 }); // padding
		writer.putInt(4096); // type index of friend function.
		writer.putNullTerminatedString("friendFunctionName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof FriendFunctionMsType, true);
		String result = type.toString().trim();
		// TODO: probably need a type other than 4096... need something that emits like a function.
		assertEquals("friend: DummyMsType friendFunctionName", result);
	}

	@Test
	public void testIndex16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Index16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // type index of friend function.
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Index16MsType, true);
		assertEquals(((Index16MsType) type).getReferencedRecordNumber().getNumber(), 4096);
		String result = type.toString().trim();
		assertEquals("index: 0x00001000", result);
	}

	@Test
	public void testIndexMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(IndexMsType.PDB_ID);
		writer.putBytes(new byte[] { 0x00, 0x00 }); // padding
		writer.putInt(4096); // type index of friend function.
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof IndexMsType, true);
		assertEquals(((AbstractIndexMsType) type).getReferencedRecordNumber().getNumber(), 4096);
		String result = type.toString().trim();
		assertEquals("index: 0x00001000", result);
	}

	@Test
	public void testMember16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		byte[] symbolBytes = createMember16MsTypeBuffer();
		writer.putBytes(symbolBytes);
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof Member16MsType, true);
		String result = type.toString().trim();
		assertEquals("public static<pseudo, noinherit, noconstruct>: DummyMsType memberName<@16>",
			result);
	}

	@Test
	public void testMemberStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		byte[] symbolBytes = createMemberStMsTypeBuffer();
		writer.putBytes(symbolBytes);
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof MemberStMsType, true);
		String result = type.toString().trim();
		assertEquals("public static<pseudo, noinherit, noconstruct>: DummyMsType memberName<@16>",
			result);
	}

	@Test
	public void testMemberMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		byte[] symbolBytes = createMemberMsTypeBuffer();
		writer.putBytes(symbolBytes);
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof MemberMsType, true);
		String result = type.toString().trim();
		assertEquals("public static<pseudo, noinherit, noconstruct>: DummyMsType memberName<@16>",
			result);
	}

	@Test
	public void testStaticMember16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(StaticMember16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // type index of field.
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putByteLengthPrefixedString("staticMemberName");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof StaticMember16MsType, true);
		String result = type.toString().trim();
		assertEquals(
			"public static<pseudo, noinherit, noconstruct>: DummyMsType" + " staticMemberName",
			result);
	}

	@Test
	public void testStaticMemberStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(StaticMemberStMsType.PDB_ID);
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(4096); // type index of field.
		writer.putByteLengthPrefixedString("staticMemberName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof StaticMemberStMsType, true);
		String result = type.toString().trim();
		assertEquals(
			"public static<pseudo, noinherit, noconstruct>: DummyMsType" + " staticMemberName",
			result);
	}

	@Test
	public void testStaticMemberMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(StaticMemberMsType.PDB_ID);
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(4096); // type index of field.
		writer.putNullTerminatedString("staticMemberName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof StaticMemberMsType, true);
		String result = type.toString().trim();
		assertEquals(
			"public static<pseudo, noinherit, noconstruct>: DummyMsType" + " staticMemberName",
			result);
	}

	@Test
	public void testOverloadedMethod16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(OverloadedMethod16MsType.PDB_ID);
		int count = ((AbstractMethodListMsType) pdb
				.getTypeRecord(RecordNumber.typeRecordNumber(methodList16MsType1))).getListSize();
		writer.putUnsignedShort(count);
		writer.putUnsignedShort(methodList16MsType1); // type index of MethodList16MsType
		writer.putByteLengthPrefixedString("overloadedMethodName");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof OverloadedMethod16MsType, true);
		String result = type.toString().trim();
		assertEquals("overloaded[2]:overloadedMethodName{<public static<pseudo, noinherit," +
			" noconstruct>: DummyMsType>,<public <intro><pseudo, noinherit, noconstruct>:" +
			" DummyMsType,8>}", result);
	}

	@Test
	public void testOverloadedMethodStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(OverloadedMethodStMsType.PDB_ID);
		int count = ((AbstractMethodListMsType) pdb
				.getTypeRecord(RecordNumber.typeRecordNumber(methodList16MsType1))).getListSize();
		writer.putUnsignedShort(count);
		writer.putInt(methodListMsType1); // type index of MethodListMsType
		writer.putByteLengthPrefixedString("overloadedMethodName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof OverloadedMethodStMsType, true);
		String result = type.toString().trim();
		assertEquals("overloaded[2]:overloadedMethodName{<public static<pseudo, noinherit," +
			" noconstruct>: DummyMsType>,<public <intro><pseudo, noinherit, noconstruct>:" +
			" DummyMsType,8>}", result);
	}

	@Test
	public void testOverloadedMethodMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(OverloadedMethodMsType.PDB_ID);
		int count = ((AbstractMethodListMsType) pdb
				.getTypeRecord(RecordNumber.typeRecordNumber(methodList16MsType1))).getListSize();
		writer.putUnsignedShort(count);
		writer.putInt(methodListMsType1); // type index of MethodListMsType
		writer.putNullTerminatedString("overloadedMethodName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof OverloadedMethodMsType, true);
		String result = type.toString().trim();
		assertEquals("overloaded[2]:overloadedMethodName{<public static<pseudo, noinherit," +
			" noconstruct>: DummyMsType>,<public <intro><pseudo, noinherit, noconstruct>:" +
			" DummyMsType,8>}", result);
	}

	@Test
	public void testNestedType16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(NestedType16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // type index of nested type
		writer.putByteLengthPrefixedString("nestedTypeName");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof NestedType16MsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType nestedTypeName", result);
	}

	@Test
	public void testNestedTypeStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(NestedTypeStMsType.PDB_ID);
		writer.putBytes(new byte[] { 0x00, 0x00 }); // padding
		writer.putInt(4096); // type index of nested type
		writer.putByteLengthPrefixedString("nestedTypeName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof NestedTypeStMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType nestedTypeName", result);
	}

	@Test
	public void testNestedTypeMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(NestedTypeMsType.PDB_ID);
		writer.putBytes(new byte[] { 0x00, 0x00 }); // padding
		writer.putInt(4096); // type index of nested type
		writer.putNullTerminatedString("nestedTypeName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof NestedTypeMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType nestedTypeName", result);
	}

	@Test
	public void testNestedTypeExtStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(NestedTypeExtStMsType.PDB_ID);
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(4096); // type index of nested type
		writer.putByteLengthPrefixedString("nestedTypeExtName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof NestedTypeExtStMsType, true);
		String result = type.toString().trim();
		assertEquals(
			"public static<pseudo, noinherit, noconstruct>:" + " DummyMsType nestedTypeExtName",
			result);
	}

	@Test
	public void testNestedTypeExtMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(NestedTypeExtMsType.PDB_ID);
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(4096); // type index of nested type
		writer.putNullTerminatedString("nestedTypeExtName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof NestedTypeExtMsType, true);
		String result = type.toString().trim();
		assertEquals(
			"public static<pseudo, noinherit, noconstruct>:" + " DummyMsType nestedTypeExtName",
			result);
	}

	@Test
	public void testVirtualFunctionTablePointer16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VirtualFunctionTablePointer16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // type index of pointer
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof VirtualFunctionTablePointer16MsType, true);
		String result = type.toString().trim();
		assertEquals("VFTablePtr: DummyMsType", result);
	}

	@Test
	public void testVirtualFunctionTablePointerMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VirtualFunctionTablePointerMsType.PDB_ID);
		writer.putBytes(new byte[] { 0x00, 0x00 }); // padding
		writer.putInt(4096); // type index of pointer
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof VirtualFunctionTablePointerMsType, true);
		String result = type.toString().trim();
		assertEquals("VFTablePtr: DummyMsType", result);
	}

	@Test
	public void testFriendClass16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(FriendClass16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // type index of pointer
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof FriendClass16MsType, true);
		String result = type.toString().trim();
		assertEquals("friend: DummyMsType", result);
	}

	@Test
	public void testFriendClassMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(FriendClassMsType.PDB_ID);
		writer.putBytes(new byte[] { 0x00, 0x00 }); // padding
		writer.putInt(4096); // type index of pointer
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof FriendClassMsType, true);
		String result = type.toString().trim();
		assertEquals("friend: DummyMsType", result);
	}

	@Test
	public void testOneMethod16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(OneMethod16MsType.PDB_ID);
		int procedureRecordNumber = 4096;
		int accessVal = 3;
		int propertyVal = 2;
		int offset = 8;
		byte[] attributesBuffer = createClassFieldMsAttributesBuffer(accessVal, propertyVal, true,
			true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putUnsignedShort(procedureRecordNumber);
		if (propertyVal == 4) {
			writer.putInt(offset);
		}
		writer.putByteLengthPrefixedString("methodName");
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof OneMethod16MsType, true);
		String result = type.toString().trim();
		assertEquals("<public static<pseudo, noinherit, noconstruct>: DummyMsType>", result);
	}

	@Test
	public void testOneMethodStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(OneMethodStMsType.PDB_ID);
		int procedureRecordNumber = 4096;
		int accessVal = 3;
		int propertyVal = 2;
		int offset = 8;
		byte[] attributesBuffer = createClassFieldMsAttributesBuffer(accessVal, propertyVal, true,
			true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(procedureRecordNumber);
		if (propertyVal == 4) {
			writer.putInt(offset);
		}
		writer.putByteLengthPrefixedString("methodName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof OneMethodStMsType, true);
		String result = type.toString().trim();
		assertEquals("<public static<pseudo, noinherit, noconstruct>: DummyMsType>", result);
	}

	@Test
	public void testOneMethodMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(OneMethodMsType.PDB_ID);
		int procedureRecordNumber = 4096;
		int accessVal = 3;
		int propertyVal = 2;
		int offset = 8;
		byte[] attributesBuffer = createClassFieldMsAttributesBuffer(accessVal, propertyVal, true,
			true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(procedureRecordNumber);
		if (propertyVal == 4) {
			writer.putInt(offset);
		}
		writer.putNullTerminatedString("methodName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof OneMethodMsType, true);
		String result = type.toString().trim();
		assertEquals("<public static<pseudo, noinherit, noconstruct>: DummyMsType>", result);
	}

	@Test
	public void testVirtualFunctionTablePointerWithOffset16MsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VirtualFunctionTablePointerWithOffset16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // type index of pointer
		writer.putInt(8); // offset
		writer.putPadding(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof VirtualFunctionTablePointerWithOffset16MsType, true);
		String result = type.toString().trim();
		assertEquals("VFTablePtr<off=8>: DummyMsType", result);
	}

	@Test
	public void testVirtualFunctionTablePointerWithOffsetMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VirtualFunctionTablePointerWithOffsetMsType.PDB_ID);
		writer.putBytes(new byte[] { 0x00, 0x00 }); // padding
		writer.putInt(4096); // type index of pointer
		writer.putInt(8); // offset
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof VirtualFunctionTablePointerWithOffsetMsType, true);
		String result = type.toString().trim();
		assertEquals("VFTablePtr<off=8>: DummyMsType", result);
	}

	@Test
	public void testMemberModifyStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(MemberModifyStMsType.PDB_ID);
		int accessVal = 3;
		int propertyVal = 2;
		byte[] attributesBuffer = createClassFieldMsAttributesBuffer(accessVal, propertyVal, true,
			true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(4096); // base class type definition index
		writer.putByteLengthPrefixedString("memberName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof MemberModifyStMsType, true);
		String result = type.toString().trim();
		assertEquals("public static<pseudo, noinherit, noconstruct>: DummyMsType memberName",
			result);
	}

	@Test
	public void testMemberModifyMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(MemberModifyMsType.PDB_ID);
		int accessVal = 3;
		int propertyVal = 2;
		byte[] attributesBuffer = createClassFieldMsAttributesBuffer(accessVal, propertyVal, true,
			true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(4096); // base class type definition index
		writer.putNullTerminatedString("memberName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof MemberModifyMsType, true);
		String result = type.toString().trim();
		assertEquals("public static<pseudo, noinherit, noconstruct>: DummyMsType memberName",
			result);
	}

	@Test
	public void testManagedStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManagedStMsType.PDB_ID);
		writer.putByteLengthPrefixedUtf8String("managedTypeName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof ManagedStMsType, true);
		String result = type.toString().trim();
		assertEquals("managedTypeName", result);
	}

	@Test
	public void testManagedMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ManagedMsType.PDB_ID);
		writer.putNullTerminatedUtf8String("managedTypeName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof ManagedMsType, true);
		String result = type.toString().trim();
		assertEquals("managedTypeName", result);
	}

	@Test
	public void testAliasStMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(AliasStMsType.PDB_ID);
		writer.putInt(4096); // underlying type index
		writer.putByteLengthPrefixedString("aliasName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof AliasStMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType aliasName", result);
	}

	@Test
	public void testAliasMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(AliasMsType.PDB_ID);
		writer.putInt(4096); // underlying type index
		writer.putNullTerminatedString("aliasName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof AliasMsType, true);
		String result = type.toString().trim();
		assertEquals("DummyMsType aliasName", result);
	}

	@Test
	public void testHighLevelShaderLanguageMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(HighLevelShaderLanguageMsType.PDB_ID);
		writer.putInt(4096); // subtype index (0 if none?)
		writer.putUnsignedShort(0x0200); // kind
		int numberOfNumericProperties = 2;
		// Number of numeric properties (4 bits) + 12 bits of padding (0)
		writer.putUnsignedShort(numberOfNumericProperties & 0x0f);
		// Guess at interpretation of what should follow.  API says:
		// "variable-length array of numeric properties followed by byte size"
		for (int i = 0; i < numberOfNumericProperties; i++) {
			writer.putInt(4096); // property.  Assuming an unknown-sized integral type. TODO.
		}
		// byte size?
		writer.putBytes(new byte[] { 0x00, 0x00 }); // padding
		//writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof HighLevelShaderLanguageMsType, true);
		String result = type.toString().trim();
		assertEquals("Built-In HLSL: InterfacePointer <numProperties=2>", result);
	}

	@Test
	public void testModifierExMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ModifierExMsType.PDB_ID);
		writer.putInt(4096); // modified type index
		int count = 18;
		writer.putUnsignedShort(count);
		int i;
		for (i = 0; i < count && i < 3; i++) {
			writer.putUnsignedShort(1 + i); // modifier.
		}
		for (; i < count; i++) {
			writer.putUnsignedShort(0x200 - 3 + i); // modifier.
		}
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof ModifierExMsType, true);
		String result = type.toString().trim();
		assertEquals("const volatile __unaligned __uniform__ __line__ __triangle__ __lineadj__" +
			" __triangleadj__ __linear__ __centroid__ __constinterp__ __noperspective__" +
			" __sample__ __center__ __snorm__ __unorm__ __precise__ __uav_globally_coherent__" +
			" DummyMsType", result);
	}

	@Test
	public void testVectorMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VectorMsType.PDB_ID);
		writer.putInt(4096); // element type index
		int elementSize = 4; // Made up
		long count = 5; // Number of elements in vector
		long size = count * elementSize;
		writer.putUnsignedInt(count);
		// TODO:
		// "Variable length data specifying size in bytes and name"
		//  Don't know size of each or if really an array of data or not.
		//  Is there a name?
		writer.putNumeric(new BigInteger(String.format("%x", size), 16), 0x800a);
		writer.putNullTerminatedString("vectorName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof VectorMsType, true);
		String result = type.toString().trim();
		assertEquals("vector: vectorName[<DummyMsType> 5]", result);
	}

	@Test
	public void testMatrixMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(MatrixMsType.PDB_ID);
		writer.putInt(4096); // element type index
		boolean rowMajor = true; // default is column-major
		int elementSize = 4; // Made up
		long numRows = 2; // Number of rows in the matrix
		long numColumns = 3; // Number columns in the matrix
		long majorStride = elementSize * (rowMajor ? numColumns : numRows);
		long size = numRows * numColumns * elementSize;
		writer.putUnsignedInt(numRows);
		writer.putUnsignedInt(numColumns);
		writer.putUnsignedInt(majorStride);
		writer.putUnsignedByte(rowMajor ? 0x00 : 0x01);
		writer.putNumeric(new BigInteger(String.format("%x", size), 16), 0x800a);
		writer.putNullTerminatedString("matrixName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof MatrixMsType, true);
		String result = type.toString().trim();
		assertEquals("matrix: matrixName[column<DummyMsType> 3][row<DummyMsType> 2]", result);
	}

	@Test
	public void testFunctionIdMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(FunctionIdMsType.PDB_ID);
		writer.putInt(4096); // scope type index
		writer.putInt(4096); // type index
		writer.putNullTerminatedString("functionIdName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof FunctionIdMsType, true);
		String result = type.toString().trim();
		assertEquals("FunctionId for: DummyMsType ItemDummyMsType::functionIdName", result);
	}

	@Test
	public void testMemberFunctionIdMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(MemberFunctionIdMsType.PDB_ID);
		writer.putInt(4096); // parent type index
		writer.putInt(4096); // type index
		writer.putNullTerminatedString("memberFunctionIdName");
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof MemberFunctionIdMsType, true);
		String result = type.toString().trim();
		assertEquals("MemberFunctionId for: DummyMsType DummyMsType::memberFunctionIdName", result);
	}

	@Test
	public void testUserDefinedTypeSourceAndLineMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(UserDefinedTypeSourceAndLineMsType.PDB_ID);
		writer.putInt(4096); // user defined type, type index
		writer.putInt(stringIdMsType1); // index to StringIdMsType record of source file name.
		writer.putUnsignedInt(1000); // Line number
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof UserDefinedTypeSourceAndLineMsType, true);
		String result = type.toString().trim();
		assertEquals(
			"UserDefinedTypeSourceAndLineMsType, line: 1000, SourceFileNameStringIdIndex:" +
				" String1, type: DummyMsType",
			result);
	}

	@Test
	public void testUserDefinedTypeModuleSourceAndLineMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(UserDefinedTypeModuleSourceAndLineMsType.PDB_ID);
		writer.putInt(4096); // user defined type, type index
		writer.putInt(1); // offset in names table of source file name.
		writer.putUnsignedInt(1000); // Line number
		writer.putUnsignedShort(1); // Module that contributes the UDT definition.
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof UserDefinedTypeModuleSourceAndLineMsType, true);
		String result = type.toString().trim();
		assertEquals("UserDefinedTypeModuleSourceAndLineMsType, module: 1, line: 1000," +
			" sourceFileName: NameTableTestString, type: DummyMsType", result);
	}

	@Test
	public void testBuildInfoMsType() throws Exception {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(BuildInfoMsType.PDB_ID);
		writer.putUnsignedShort(5); // number of arguments
		writer.putInt(stringIdMsType1); // value for argument 0.
		writer.putInt(stringIdMsType2); // value for argument 1.
		writer.putInt(stringIdMsType1); // value for argument 2.
		writer.putInt(stringIdMsType2); // value for argument 3.
		writer.putInt(stringIdMsType1); // value for argument 4.
		writer.putAlign(2);
		PdbByteReader reader = new PdbByteReader(writer.get());
		AbstractMsType type = TypeParser.parse(pdb, reader);
		assertEquals(type instanceof BuildInfoMsType, true);
		String result = type.toString().trim();
		assertEquals("CurrentDirectory: String1, BuildTool: String2, SourceFile: String1," +
			" ProgramDatabaseFile: String2, CommandArguments: String1", result);
	}

	//==============================================================================================
	// Private Methods
	//==============================================================================================
	private static byte[] createMsPropertyBuffer() {
		byte[] bytes = new byte[2];
		bytes[0] = 0x03; // packed and ctors/dtors present.
		bytes[1] = 0x00;
		return bytes;
	}

	private static byte[] createFunctionMsAttributesBuffer() {
		byte[] bytes = new byte[1];
		bytes[0] = 0x07;
		return bytes;
	}

	// accessVal:
	//    none=0,private=1,protected=2,public=3
	// propertyVal:
	//    none=0, virtual=1,static=2,friend=3,<intro>=4,<pure>=5,<intro,pure>=6,reserved=7
	private static byte[] createClassFieldMsAttributesBuffer(int accessVal, int propertyVal,
			boolean compilerGenerateFunctionDoesNotExist, boolean cannotBeInherited,
			boolean cannotBeConstructed, boolean compilerGenerateFunctionDoesExist,
			boolean cannotBeOverriden) {
		int attributes = 0;
		attributes |= (cannotBeOverriden ? 1 : 0);
		attributes <<= 1;
		attributes |= (compilerGenerateFunctionDoesExist ? 1 : 0);
		attributes <<= 1;
		attributes |= (cannotBeConstructed ? 1 : 0);
		attributes <<= 1;
		attributes |= (cannotBeInherited ? 1 : 0);
		attributes <<= 1;
		attributes |= (compilerGenerateFunctionDoesNotExist ? 1 : 0);
		attributes <<= 3;
		attributes |= (propertyVal & 0x0007);
		attributes <<= 2;
		attributes |= (accessVal & 0x0003);
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(attributes);
		return writer.get();
	}

	private static byte[] createMethod16Record(int procedureRecordNumber, int accessVal,
			int propertyVal, int offset) {
		PdbByteWriter writer = new PdbByteWriter();
		byte[] attributesBuffer = createClassFieldMsAttributesBuffer(accessVal, propertyVal, true,
			true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putUnsignedShort(procedureRecordNumber);
		if (propertyVal == 4) {
			writer.putInt(offset);
		}
		return writer.get();
	}

	private static byte[] createMethodRecord(int procedureRecordNumber, int accessVal,
			int propertyVal, int offset) {
		PdbByteWriter writer = new PdbByteWriter();
		byte[] attributesBuffer = createClassFieldMsAttributesBuffer(accessVal, propertyVal, true,
			true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putBytes(new byte[] { 0x00, 0x00 }); // padding
		writer.putInt(procedureRecordNumber);
		if (propertyVal == 4) {
			writer.putInt(offset);
		}
		return writer.get();
	}

	private static byte[] createMethodList16MsTypeBuffer() {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(MethodList16MsType.PDB_ID);
		int count = 2;
		int access = 3;
		int property = 2;
		int procedureRecordNumber = 4096;
		int offset = 8;
		for (int i = 0; i < count; i++) {
			byte[] bytes = createMethod16Record(procedureRecordNumber, access, property, offset);
			writer.putBytes(bytes);
			property = (property == 2) ? 4 : 2; // alternating
		}
		return writer.get();
	}

	private static byte[] createMethodListMsTypeBuffer() {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(MethodListMsType.PDB_ID);
		int count = 2;
		int access = 3;
		int property = 2;
		int procedureRecordNumber = 4096;
		int offset = 8;
		for (int i = 0; i < count; i++) {
			byte[] bytes = createMethodRecord(procedureRecordNumber, access, property,
				(property == 4) ? offset : -1);
			writer.putBytes(bytes);
			property = (property == 2) ? 4 : 2; // alternating
		}
		return writer.get();
	}

	private static byte[] createStringIdMsTypeBuffer(int substringListRecordId, String tailString) {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(StringIdMsType.PDB_ID);
		writer.putUnsignedInt(substringListRecordId);
		writer.putNullTerminatedString(tailString);
		writer.putAlign(2);
		return writer.get();
	}

	private static byte[] createSubstringListMsTypeBuffer(int[] stringIdRecordList) {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(SubstringListMsType.PDB_ID);
		writer.putUnsignedInt(stringIdRecordList.length);
		for (int element : stringIdRecordList) {
			writer.putUnsignedInt(element);
		}
		writer.putAlign(2);
		return writer.get();
	}

	private static byte[] createReferencedSymbolMsTypeBuffer() {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(ReferencedSymbolMsType.PDB_ID);
		// Doing a RegisterMsSymbol here.
		PdbByteWriter symbolWriter = new PdbByteWriter();
		symbolWriter.putUnsignedShort(RegisterMsSymbol.PDB_ID); // symbol record type index
		symbolWriter.putInt(4096); // type index
		symbolWriter.putUnsignedShort(0x01); // register number
		symbolWriter.putNullTerminatedUtf8String("registerSymbolName");
		symbolWriter.putAlign(0);
		byte[] symbolBytes = symbolWriter.get();
		// Write the symbol bytes, including length.
		writer.putUnsignedShort(symbolBytes.length); // length
		writer.putBytes(symbolBytes);
		return writer.get();
	}

	private static byte[] createBaseClass16MsTypeBuffer() {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(BaseClass16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // type index of base class
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putNumeric(new BigInteger("10", 16), 0x8002); //offset of base class within class
		return writer.get();
	}

	private static byte[] createBaseClassMsTypeBuffer() {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(BaseClassMsType.PDB_ID);
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(4096); // type index of base class
		writer.putNumeric(new BigInteger("10", 16), 0x8002); //offset of base class within class
		return writer.get();
	}

	private static byte[] createMember16MsTypeBuffer() {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(Member16MsType.PDB_ID);
		writer.putUnsignedShort(4096); // type index of field.
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // Offset of field.
		writer.putByteLengthPrefixedString("memberName");
		return writer.get();
	}

	private static byte[] createMemberStMsTypeBuffer() {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(MemberStMsType.PDB_ID);
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(4096); // type index of field.
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // Offset of field.
		writer.putByteLengthPrefixedString("memberName");
		return writer.get();
	}

	private static byte[] createMemberMsTypeBuffer() {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(MemberMsType.PDB_ID);
		int attributes = 3;
		int property = 2;
		byte[] attributesBuffer =
			createClassFieldMsAttributesBuffer(attributes, property, true, true, true, true, true);
		writer.putBytes(attributesBuffer);
		writer.putInt(4096); // type index of field.
		writer.putNumeric(new BigInteger("10", 16), 0x8002); // Offset of field.
		writer.putNullTerminatedString("memberName");
		return writer.get();
	}

	private static byte[] createVtShapeMsTypeBuffer() {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(VtShapeMsType.PDB_ID);
		writer.putUnsignedShort(0x07); // Count of descriptors.
		writer.putUnsignedByte(0x01); // Two descriptors.
		writer.putUnsignedByte(0x23); // Two descriptors.
		writer.putUnsignedByte(0x45); // Two descriptors.
		writer.putUnsignedByte(0x67); // One descriptor (last is dummy= unused).
		writer.putPadding(2);
		writer.putAlign(2); // TODO: Not sure
		return writer.get();
	}

}
