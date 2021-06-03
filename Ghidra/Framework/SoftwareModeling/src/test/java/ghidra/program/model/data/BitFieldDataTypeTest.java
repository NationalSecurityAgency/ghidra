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

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.docking.settings.*;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;

public class BitFieldDataTypeTest extends AbstractGTest {

	@Test
	public void testGetBaseSize() throws Exception {
		assertEquals(1, new BitFieldDataType(CharDataType.dataType, 1).getBaseTypeSize());
		assertEquals(1, new BitFieldDataType(UnsignedCharDataType.dataType, 1).getBaseTypeSize());
		assertEquals(2, new BitFieldDataType(ShortDataType.dataType, 1).getBaseTypeSize());
		assertEquals(2, new BitFieldDataType(UnsignedShortDataType.dataType, 1).getBaseTypeSize());
		assertEquals(4, new BitFieldDataType(IntegerDataType.dataType, 1).getBaseTypeSize());
		assertEquals(4,
			new BitFieldDataType(UnsignedIntegerDataType.dataType, 1).getBaseTypeSize());
	}

	@Test
	public void testGetName() throws Exception {
		assertEquals("char:1", new BitFieldDataType(CharDataType.dataType, 1).getName());
		assertEquals("uchar:2", new BitFieldDataType(UnsignedCharDataType.dataType, 2).getName());
		assertEquals("short:3", new BitFieldDataType(ShortDataType.dataType, 3).getName());
		assertEquals("ushort:4", new BitFieldDataType(UnsignedShortDataType.dataType, 4).getName());
		assertEquals("int:5", new BitFieldDataType(IntegerDataType.dataType, 5).getName());
		assertEquals("uint:6", new BitFieldDataType(UnsignedIntegerDataType.dataType, 6).getName());
	}

	@Test
	public void testGetBaseDataType() throws Exception {
		assertEquals(new CharDataType(),
			new BitFieldDataType(CharDataType.dataType, 1).getBaseDataType());
		assertEquals(new UnsignedCharDataType(),
			new BitFieldDataType(UnsignedCharDataType.dataType, 1).getBaseDataType());
		assertEquals(new ShortDataType(),
			new BitFieldDataType(ShortDataType.dataType, 1).getBaseDataType());
		assertEquals(new UnsignedShortDataType(),
			new BitFieldDataType(UnsignedShortDataType.dataType, 1).getBaseDataType());
		assertEquals(new IntegerDataType(),
			new BitFieldDataType(IntegerDataType.dataType, 1).getBaseDataType());
		assertEquals(new UnsignedIntegerDataType(),
			new BitFieldDataType(UnsignedIntegerDataType.dataType, 1).getBaseDataType());

		DataType typeDef = new TypedefDataType("Foo", LongDataType.dataType);
		BitFieldDataType bf = new BitFieldDataType(typeDef, 1);
		assertEquals(typeDef, bf.getBaseDataType());
		assertEquals(typeDef, bf.clone(null).getBaseDataType());

		EnumDataType enumDt = new EnumDataType("MyEnum", 1);
		enumDt.add("A", 0);
		enumDt.add("B", 1);
		enumDt.add("C", 2);
		enumDt.add("D", 4);
		bf = new BitFieldDataType(enumDt, 4);
		assertEquals(enumDt, bf.getBaseDataType());
		assertEquals(enumDt, bf.clone(null).getBaseDataType());

	}

	@Test
	public void testClone() throws Exception {

		BitFieldDataType bf = new BitFieldDataType(UnsignedIntegerDataType.dataType, 1);
		assertEquals(UnsignedIntegerDataType.dataType, bf.getBaseDataType());
		BitFieldDataType bfClone = bf.clone(null);
		assertEquals(UnsignedIntegerDataType.dataType, bfClone.getBaseDataType());
		assertEquals(bfClone, bf);

		DataType typeDef = new TypedefDataType("Foo", LongDataType.dataType);
		bf = new BitFieldDataType(typeDef, 1);
		assertEquals(typeDef, bf.getBaseDataType());
		bfClone = bf.clone(null);
		assertEquals(typeDef, bfClone.getBaseDataType());
		assertEquals(bfClone, bf);
	}

	@Test
	public void testGetBitSize() throws Exception {
		assertEquals(1, new BitFieldDataType(CharDataType.dataType, 1).getBitSize());
		assertEquals(2, new BitFieldDataType(UnsignedCharDataType.dataType, 2).getBitSize());
		assertEquals(3, new BitFieldDataType(ShortDataType.dataType, 3).getBitSize());
		assertEquals(4, new BitFieldDataType(UnsignedShortDataType.dataType, 4).getBitSize());
		assertEquals(5, new BitFieldDataType(IntegerDataType.dataType, 5).getBitSize());
		assertEquals(6, new BitFieldDataType(UnsignedIntegerDataType.dataType, 6).getBitSize());
	}

//	@Test
//	public void testGetBitOffset() throws Exception {
//		assertEquals(0,
//			new BitFieldDataType(IntegerDataType.dataType, 1, null).deriveBitField(0, 4, 1, 4).getBitOffset());
//		assertEquals(1,
//			new BitFieldDataType(IntegerDataType.dataType, 2, null).deriveBitField(1, 4, 1, 4).getBitOffset());
//		assertEquals(2,
//			new BitFieldDataType(IntegerDataType.dataType, 3, null).deriveBitField(2, 4, 1, 4).getBitOffset());
//		assertEquals(3,
//			new BitFieldDataType(IntegerDataType.dataType, 4, null).deriveBitField(3, 4, 1, 4).getBitOffset());
//		assertEquals(4,
//			new BitFieldDataType(IntegerDataType.dataType, 5, null).deriveBitField(4, 4, 1, 4).getBitOffset());
//		assertEquals(5,
//			new BitFieldDataType(IntegerDataType.dataType, 6, null).deriveBitField(5, 4, 1, 4).getBitOffset());
//	}

	@Test
	public void testGetValueWithSignedBaseType() throws Exception {
		assertEquals(-1, getValue(bitField(1, 0), 0x55));
		assertEquals(0, getValue(bitField(1, 1), 0x55));
		assertEquals(1, getValue(bitField(2, 0), 0x55));
		assertEquals(-3, getValue(bitField(3, 0), 0x55));
		assertEquals(5, getValue(bitField(4, 0), 0x55));
	}

	@Test
	public void testGetValueWithUnsignedBaseType() throws Exception {
		assertEquals(1, getValue(unsignedBitField(1, 0), 0x55));
		assertEquals(0, getValue(unsignedBitField(1, 1), 0x55));
		assertEquals(1, getValue(unsignedBitField(2, 0), 0x55));
		assertEquals(5, getValue(unsignedBitField(3, 0), 0x55));
		assertEquals(5, getValue(unsignedBitField(4, 0), 0x55));
	}

	@Test
	public void testHexRepresentationSignedBaseType() throws Exception {
		assertEquals("1h", getRepresentation(bitField(1, 0), 0x55));
		assertEquals("0h", getRepresentation(bitField(1, 1), 0x55));
		assertEquals("1h", getRepresentation(bitField(2, 0), 0x55));
		assertEquals("5h", getRepresentation(bitField(3, 0), 0x55));
		assertEquals("5h", getRepresentation(bitField(4, 0), 0x55));
	}

	@Test
	public void testDecimalRepresentationSignedBaseType() throws Exception {
		assertEquals("-1", getDecimalRepresentation(bitField(1, 0), 0x55));
		assertEquals("0", getDecimalRepresentation(bitField(1, 1), 0x55));
		assertEquals("1", getDecimalRepresentation(bitField(2, 0), 0x55));
		assertEquals("-3", getDecimalRepresentation(bitField(3, 0), 0x55));
		assertEquals("5", getDecimalRepresentation(bitField(4, 0), 0x55));
	}

	@Test
	public void testDecimalRepresentationUnsignedBaseType() throws Exception {
		assertEquals("1", getDecimalRepresentation(unsignedBitField(1, 0), 0x55));
		assertEquals("0", getDecimalRepresentation(unsignedBitField(1, 1), 0x55));
		assertEquals("1", getDecimalRepresentation(unsignedBitField(2, 0), 0x55));
		assertEquals("5", getDecimalRepresentation(unsignedBitField(3, 0), 0x55));
		assertEquals("5", getDecimalRepresentation(unsignedBitField(4, 0), 0x55));
	}

	@Test
	public void testEnumRepresentation() throws Exception {

		EnumDataType enumDt = new EnumDataType("MyEnum", 1);
		enumDt.add("A", 1);
		enumDt.add("B", 2);
		enumDt.add("C", 4);
		enumDt.add("D", 8);
		BitFieldDataType bf = new BitFieldDataType(enumDt, 4);
		assertEquals(enumDt, bf.getBaseDataType());
		assertEquals(enumDt, bf.clone(null).getBaseDataType());

		assertEquals("A | B | C | D", getRepresentation(bf, 0x0f));
	}

	private String getRepresentation(BitFieldDataType bitField, int... unsignedBytes)
			throws Exception {
		MemBuffer membuf = membuf(unsignedBytes);
		return bitField.getRepresentation(membuf, null, 4);
	}

	private String getDecimalRepresentation(BitFieldDataType bitField, int... bytes)
			throws Exception {
		MemBuffer membuf = membuf(bytes);
		Settings settings = new SettingsImpl();
		FormatSettingsDefinition.DEF_DECIMAL.setDisplayChoice(settings, "decimal");
		return bitField.getRepresentation(membuf, settings, bitField.getStorageSize());
	}

	private int getValue(BitFieldDataType bitField, int... bytes) throws Exception {
		MemBuffer membuf = membuf(bytes);
		Scalar scalar = (Scalar) bitField.getValue(membuf, null, bitField.getStorageSize());
		return (int) scalar.getValue();
	}

	private BitFieldDataType bitField(int size, int offset) throws Exception {
		return new BitFieldDataType(IntegerDataType.dataType, size, offset);
	}

	private BitFieldDataType unsignedBitField(int size, int offset) throws Exception {
		return new BitFieldDataType(UnsignedIntegerDataType.dataType, size, offset);
	}

	private MemBuffer membuf(int... unsignedBytes) throws Exception {
		return new ByteMemBufferImpl(null, bytes(unsignedBytes), true);
	}

}
