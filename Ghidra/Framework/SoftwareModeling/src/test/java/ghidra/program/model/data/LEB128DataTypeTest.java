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

import static ghidra.program.model.data.LEB128Test.te;
import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.LEB128Test.TestEntry;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;

public class LEB128DataTypeTest extends AbstractGenericTest {

	static SettingsBuilder HEX_SETTINGS = new SettingsBuilder()
			.setFormat(FormatSettingsDefinition.HEX, AbstractLeb128DataType.FORMAT);
	static SettingsBuilder DECIMAL_SETTINGS = new SettingsBuilder()
			.setFormat(FormatSettingsDefinition.DECIMAL, AbstractLeb128DataType.FORMAT);

	@Test
	public void testStringRep() throws IOException {

		assertRepresentation(te(1L, 0x01), false, "1h", "1");
		assertRepresentation(te(0L, 0x80, 0x80, 0x80, 0x80, 0x80, 0x0), false, "0h", "0");
		assertRepresentation(te(1L, 0x81, 0x80, 0x80, 0x80, 0x80, 0x0), false, "1h", "1");
		assertRepresentation(te(-1L, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01),
			false, "FFFFFFFFFFFFFFFFh", "18446744073709551615");
		assertRepresentation(te(63L, 0x3f), false, "3Fh", "63");
		assertRepresentation(te(128L, 0x80, 0x01), false, "80h", "128");
		assertRepresentation(te(2097151L, 0xff, 0xff, 0x7f), false, "1FFFFFh", "2097151");

		assertRepresentation(te(-1L, 0x7f), true, "-1h", "-1");
		assertRepresentation(te(-2L, 0x7e), true, "-2h", "-2");
		assertRepresentation(te(-64L, 0x40), true, "-40h", "-64");
		assertRepresentation(te(-127, 0x81, 0x7f), true, "-7Fh", "-127");
		assertRepresentation(te(-128, 0x80, 0x7f), true, "-80h", "-128");
		assertRepresentation(te(-8193L, 0xff, 0xbf, 0x7f), true, "-2001h", "-8193");
	}

	@Test
	public void testNotEnoughBytes() throws IOException {
		// tests what happens when this var length data type is contained within a dtc
		// that is too small for what the data demands.
		MemBuffer mb = te(0L, 0x80, 0x0, 0x0, 0x0).mb();
		UnsignedLeb128DataType uleb128 = UnsignedLeb128DataType.dataType;
		Scalar value = (Scalar) uleb128.getValue(mb, HEX_SETTINGS, 1);
		String hexRep = uleb128.getRepresentation(mb, HEX_SETTINGS, 1);

		assertNull(value);
		assertEquals("??", hexRep);
	}

	@Test
	public void testTooManyBytes() throws IOException {
		// tests what happens when this var length data type is contained within a dtc
		// that has more bytes than what the data demands.
		MemBuffer mb = te(0L, 0x80, 0x0, 0x0, 0x0).mb();
		UnsignedLeb128DataType uleb128 = UnsignedLeb128DataType.dataType;
		Scalar value = (Scalar) uleb128.getValue(mb, HEX_SETTINGS, 4);
		String hexRep = uleb128.getRepresentation(mb, HEX_SETTINGS, 4);

		assertEquals(0, value.getUnsignedValue());
		assertEquals("0h", hexRep);
	}

	@Test
	public void testGetValueWithoutLength() throws IOException {
		MemBuffer mb = te(0L, 0x80, 0x0, 0x0, 0x0).mb();
		UnsignedLeb128DataType uleb128 = UnsignedLeb128DataType.dataType;
		Scalar value = (Scalar) uleb128.getValue(mb, HEX_SETTINGS, -1);
		assertNotNull(value);
	}

	private void assertRepresentation(TestEntry te, boolean signed, String hexExpected,
			String decExpected) throws IOException {

		MemBuffer mb = te.mb();
		//Scalar value = (Scalar) dt.getValue(mb, settings, length);
		AbstractLeb128DataType lebdt = signed
				? SignedLeb128DataType.dataType
				: UnsignedLeb128DataType.dataType;
		int length = lebdt.getLength(mb, -1);
		//Scalar value = (Scalar) dt.getValue(mb, settings, length);
		String hexRep = lebdt.getRepresentation(mb, HEX_SETTINGS, length);
		String decRep = lebdt.getRepresentation(mb, DECIMAL_SETTINGS, length);

		assertEquals(te.bytes().length, length);
		assertEquals(hexExpected, hexRep);
		assertEquals(decExpected, decRep);
	}
}
