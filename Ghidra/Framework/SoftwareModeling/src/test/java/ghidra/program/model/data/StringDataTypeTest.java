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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.docking.settings.Settings;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.RenderUnicodeSettingsDefinition.RENDER_ENUM;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;

public class StringDataTypeTest extends AbstractGTest {

	private StringDataType fixedlenString = new StringDataType();
	private StringUTF8DataType fixedUtf8String = new StringUTF8DataType();
	private UnicodeDataType fixedUtf16String = new UnicodeDataType();
	private Unicode32DataType fixedUtf32String = new Unicode32DataType();

	private TerminatedStringDataType termString = new TerminatedStringDataType();
	private TerminatedUnicodeDataType termUtf16String = new TerminatedUnicodeDataType();
	private TerminatedUnicode32DataType termUtf32String = new TerminatedUnicode32DataType();

	private PascalString255DataType pascal255String = new PascalString255DataType();
	private PascalStringDataType pascalString = new PascalStringDataType();
	private PascalUnicodeDataType pascalUtf16String = new PascalUnicodeDataType();

	private static class DataOrgDTM extends TestDummyDataTypeManager {
		private DataOrganization dataOrg;

		public DataOrgDTM(DataOrganization dataOrg) {
			this.dataOrg = dataOrg;
		}

		@Override
		public DataOrganization getDataOrganization() {
			return dataOrg;
		}
	}

	private ByteMemBufferImpl mb(boolean isBE, int... values) {
		GenericAddressSpace gas = new GenericAddressSpace("test", 32, AddressSpace.TYPE_RAM, 1);
		return new ByteMemBufferImpl(gas.getAddress(0), bytes(values), isBE);
	}

	private SettingsBuilder newset() {
		return new SettingsBuilder();
	}

	private StringDataInstance mkSDI(AbstractStringDataType dt, MemBuffer buf, Settings settings,
			int length) {
		return new StringDataInstance(dt, settings, buf, length);
	}

	//-------------------------------------------------------------------------------------
	// get string length
	//-------------------------------------------------------------------------------------
	@Test
	public void testProbeGetStringLen() {
		ByteMemBufferImpl buf = mb(false, 'h', 'e', 'l', 'l', 'o', 0, 'x', 'y', 0);

		// all probes with unknown len are null-term string probes
		assertEquals(6, fixedlenString.getLength(buf, -1));
		assertEquals(6, termString.getLength(buf, -1));
		assertEquals(6, fixedUtf8String.getLength(buf, -1));
	}

	@Test
	public void testProbeGetStringLen_EOF() {
		ByteMemBufferImpl buf = mb(false, 'h', 'e', 'l', 'l', 'o');

		// terminated string probe should fail if hit EOF before null-term char
		assertEquals(-1, fixedlenString.getLength(buf, -1));
		assertEquals(-1, termString.getLength(buf, -1));
	}

	@Test
	public void testProbeGetStringLen_utf16() {
		ByteMemBufferImpl buf = mb(false, //
			'h', 0, //
			'e', 0, //
			'l', 0, //
			'l', 0, //
			'o', 0, //
			0, 0, //
			'x', 0, //
			'y', 0);

		// all probes with unknown len are null-term string probes
		assertEquals(12, fixedUtf16String.getLength(buf, -1));
		assertEquals(12, termUtf16String.getLength(buf, -1));
	}

	@Test
	public void testProbeGetStringLen_utf32() {
		ByteMemBufferImpl buf = mb(false, //
			'h', 0, 0, 0, //
			'e', 0, 0, 0, //
			'l', 0, 0, 0, //
			'l', 0, 0, 0, //
			'o', 0, 0, 0, //
			0, 0, 0, 0, //
			'x', 0, 0, 0, //
			'y', 0, 0, 0);

		// all probes with unknown len are null-term string probes
		assertEquals(24, fixedUtf32String.getLength(buf, -1));
		assertEquals(24, termUtf32String.getLength(buf, -1));
	}

	@Test
	public void testProbeGetStringLen_P255() {
		ByteMemBufferImpl buf = mb(false, 5, 'h', 'e', 'l', 'l', 'o', 'x', 'y', 0);

		assertEquals(6, pascal255String.getLength(buf, -1));
		assertEquals(6, pascal255String.getLength(buf, buf.getLength()));
	}

	@Test
	public void testProbeGetStringLen_P() {
		ByteMemBufferImpl buf = mb(false, 5, 0, 'h', 'e', 'l', 'l', 'o', 'x', 'y', 0);

		assertEquals(7, pascalString.getLength(buf, -1));
		assertEquals(7, pascalString.getLength(buf, buf.getLength()));
	}

	@Test
	public void testProbeGetStringLen_utf16P() {
		ByteMemBufferImpl buf =
			mb(false, 5, 0, 'h', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0, 'x', 0, 'y', 0, 0);

		assertEquals(12, pascalUtf16String.getLength(buf, -1));
		assertEquals(12, pascalUtf16String.getLength(buf, buf.getLength()));
	}

	@Test
	public void testKnownGetStringLen() {
		ByteMemBufferImpl buf = mb(false, 'h', 'e', 'l', 'l', 'o', 0, 'x', 'y', 0);

		assertEquals(6, termString.getLength(buf, buf.getLength()));
		assertEquals(6, termString.getLength(buf, 1));

		assertEquals(1, fixedlenString.getLength(buf, 1));
		assertEquals(6, fixedlenString.getLength(buf, 6));
		assertEquals(7, fixedlenString.getLength(buf, 7));

		assertEquals(1, fixedUtf8String.getLength(buf, 1));
		assertEquals(6, fixedUtf8String.getLength(buf, 6));
		assertEquals(7, fixedUtf8String.getLength(buf, 7));
	}

	@Test
	public void testProbeOversizeStringLen() {
		int[] chars = new int[StringDataInstance.MAX_STRING_LENGTH + 1];
		Arrays.fill(chars, 'a');
		chars[chars.length - 1] = '\0';
		ByteMemBufferImpl buf = mb(false, chars);

		assertEquals("Should fail when trying to find null term with strings larger than 16k", -1,
			termString.getLength(buf, buf.getLength()));

		chars[chars.length - 2] = '\0';
		buf = mb(false, chars);

		assertEquals("Should work when trying to find null term with strings smaller than 16k",
			StringDataInstance.MAX_STRING_LENGTH, termString.getLength(buf, buf.getLength()));
	}

	//-----------------------------------------------------------------------------------
	// stringValue
	//-----------------------------------------------------------------------------------
	@Test
	public void testProbeGetStringValue() {
		ByteMemBufferImpl buf = mb(false, 'h', 'e', 'l', 'l', 'o', 0, 'x', 'y', 0);

		// getValue always returns null with unknown string field length
		assertEquals(null, fixedlenString.getValue(buf, newset(), -1));
		assertEquals(null, termString.getValue(buf, newset(), -1));
	}

	@Test
	public void testGetStringValue() {
		ByteMemBufferImpl buf = mb(false, 'h', 'e', 'l', 'l', 'o', 0, 'x', 'y', 0);

		// term & unbounded should get the first null term string regardless of containing field length
		assertEquals("hello", termString.getValue(buf, newset(), 1));
		assertEquals("hello", termString.getValue(buf, newset(), 5));
		assertEquals("hello", termString.getValue(buf, newset(), 6));
		assertEquals("hello", termString.getValue(buf, newset(), buf.getLength()));

		// fixedlen & bounded should get exactly what len param specifies
		assertEquals("h", fixedlenString.getValue(buf, newset(), 1));
		assertEquals("hello", fixedlenString.getValue(buf, newset(), 5));
		assertEquals("hello", fixedlenString.getValue(buf, newset(), 6));
		assertEquals("hello\0xy", fixedlenString.getValue(buf, newset(), buf.getLength()));
	}

	@Test
	public void testGetStringValue_utf8() {
		// "ab" and 2 ideographic characters cc01 & 1202 encoded as UTF-8
		ByteMemBufferImpl buf = mb(false, 'a', 'b', 0xec, 0xb0, 0x81, 0xe1, 0x88, 0x82);

		String actual = (String) fixedUtf8String.getValue(buf, newset(), buf.getLength());

		assertEquals("ab\ucc01\u1202", actual);
	}

	@Test
	public void testGetStringValue_utf8_2bytechar_dataorg() {
		// test UTF-8 when the dataorg specifies a 2byte character (ie. JVM)
		ByteMemBufferImpl buf = mb(false, 'a', 'b', 'c');

		DataOrganizationImpl dataOrg = DataOrganizationImpl.getDefaultOrganization(null);
		dataOrg.setCharSize(2);
		DataOrgDTM dtm = new DataOrgDTM(dataOrg);
		StringUTF8DataType wideCharUTF8DT = new StringUTF8DataType(dtm);

		String actual = (String) wideCharUTF8DT.getValue(buf, newset(), buf.getLength());

		assertEquals("abc", actual);
	}

	@Test
	public void testGetStringValue_utf16_le() {
		ByteMemBufferImpl buf = mb(false, //
			'h', 0, //
			'e', 0, //
			'l', 0, //
			'l', 0, //
			'o', 0, //
			0, 0, //
			'x', 0, //
			'y', 0);

		// term & unbounded should get the first null term string regardless of containing field
		assertEquals("hello", termUtf16String.getValue(buf, newset(), 1 * 2));
		assertEquals("hello", termUtf16String.getValue(buf, newset(), 5 * 2));
		assertEquals("hello", termUtf16String.getValue(buf, newset(), 6 * 2));
		assertEquals("hello", termUtf16String.getValue(buf, newset(), buf.getLength()));

		// fixedlen & bounded should get exactly what len param specifies
		assertEquals("h", fixedUtf16String.getValue(buf, newset(), 1 * 2));
		assertEquals("hello", fixedUtf16String.getValue(buf, newset(), 5 * 2));
		assertEquals("hello", fixedUtf16String.getValue(buf, newset(), 6 * 2));
		assertEquals("hello\0xy", fixedUtf16String.getValue(buf, newset(), buf.getLength()));
	}

	@Test
	public void testGetStringValue_utf_bom() {
		// test reading BE and LE utf-* string that is determined by the BOM at the start of the string.
		assertEquals("A", fixedUtf16String.getValue(mb(false, 0xfe, 0xff, 0, 'A'), newset(), 4));// BE BOM
		assertEquals("A", fixedUtf16String.getValue(mb(false, 0xff, 0xfe, 'A', 0), newset(), 4));// LE BOM
		assertEquals("A", fixedUtf32String.getValue(mb(false, 0x00, 0x00, 0xfe, 0xff, 0, 0, 0, 'A'),
			newset(), 8));// BE BOM
		assertEquals("A", fixedUtf32String.getValue(mb(false, 0xff, 0xfe, 0x00, 0x00, 'A', 0, 0, 0),
			newset(), 8));// LE BOM

		// test reading BE and LE utf-* string with missing BOM and relying on mem endianness
		assertEquals("A", fixedUtf16String.getValue(mb(true, 0, 'A'), newset(), 2));// BE mem
		assertEquals("A", fixedUtf16String.getValue(mb(false, 'A', 0), newset(), 2));// LE mem
		assertEquals("A", fixedUtf32String.getValue(mb(true, 0, 0, 0, 'A'), newset(), 4));// BE mem
		assertEquals("A", fixedUtf32String.getValue(mb(false, 'A', 0, 0, 0), newset(), 4));// LE mem
	}

	@Test
	public void testGetStringValue_utf32() {
		ByteMemBufferImpl buf = mb(false, //
			'h', 0, 0, 0, //
			'e', 0, 0, 0, //
			'l', 0, 0, 0, //
			'l', 0, 0, 0, //
			'o', 0, 0, 0, //
			0, 0, 0, 0, //
			'x', 0, 0, 0, //
			'y', 0, 0, 0);

		// term & unbounded should get the first null term string regardless of containing field
		assertEquals("hello", termUtf32String.getValue(buf, newset(), 1 * 4));
		assertEquals("hello", termUtf32String.getValue(buf, newset(), 5 * 4));
		assertEquals("hello", termUtf32String.getValue(buf, newset(), 6 * 4));
		assertEquals("hello", termUtf32String.getValue(buf, newset(), buf.getLength()));

		// fixedlen & bounded should get exactly what len param specifies (minus any trailing null chars)
		assertEquals("h", fixedUtf32String.getValue(buf, newset(), 1 * 4));
		assertEquals("hello", fixedUtf32String.getValue(buf, newset(), 5 * 4));
		assertEquals("hello", fixedUtf32String.getValue(buf, newset(), 6 * 4));
		assertEquals("hello\0xy", fixedUtf32String.getValue(buf, newset(), buf.getLength()));
	}

	@Test
	public void testGetStringValue_P255() {
		ByteMemBufferImpl buf = mb(false, 5, 'h', 'e', 'l', 'l', 'o', 'x', 'y', 0);

		assertEquals(null, pascal255String.getValue(buf, newset(), -1));
		assertEquals("hello", pascal255String.getValue(buf, newset(), 1));
		assertEquals("hello", pascal255String.getValue(buf, newset(), buf.getLength()));
	}

	@Test
	public void testGetStringValue_Pascal_EOF() {
		assertEquals("Pascal string with length past end of mem should return null", null,
			pascal255String.getValue(mb(false, 5, 'h', 'e', 'l', 'l'), newset(), -1));

		assertEquals("Pascal string with length past end of mem should return null", null,
			pascalString.getValue(mb(false, 5, 0, 'h', 'e', 'l', 'l'), newset(), -1));

		assertEquals("Pascal string with length past end of mem should return null", null,
			pascalUtf16String.getValue(mb(false, 5, 0, 'h', 0), newset(), -1));
	}

	@Test
	public void testGetStringValue_P() {
		ByteMemBufferImpl buf = mb(false, 5, 0, 'h', 'e', 'l', 'l', 'o', 'x', 'y', 0);

		assertEquals(null, pascalString.getValue(buf, newset(), -1));
		assertEquals("hello", pascalString.getValue(buf, newset(), 1));
		assertEquals("hello", pascalString.getValue(buf, newset(), buf.getLength()));
	}

	@Test
	public void testGetStringValue_utf16P() {
		ByteMemBufferImpl buf =
			mb(false, 5, 0, 'h', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0, 'x', 0, 'y', 0, 0);

		assertEquals(null, pascalUtf16String.getValue(buf, newset(), -1));
		assertEquals("hello", pascalUtf16String.getValue(buf, newset(), 1));
		assertEquals("hello", pascalUtf16String.getValue(buf, newset(), buf.getLength()));
	}

	//-----------------------------------------------------------------------------------
	// getRepresentation
	//-----------------------------------------------------------------------------------
	@Test
	public void testProbeGetStringRep_Probe() {
		ByteMemBufferImpl buf = mb(false, 'h', 'e', 'l', 'l', 'o', 0, 'x', 'y', 0);

		// getRep always returns error str with unknown string field length
		assertEquals("??", fixedlenString.getRepresentation(buf, newset(), -1));
	}

	@Test
	public void testProbeGetStringRep_LeadingBinaryBytes() {
		ByteMemBufferImpl buf = mb(false, 1, 2, 'x');

		assertEquals("01h,02h,\"x\"",
			fixedlenString.getRepresentation(buf, newset(), buf.getLength()));
	}

	@Test
	public void testProbeEncodeStringRep_LeadingBinaryBytes() throws DataTypeEncodeException {
		byte[] bytes = bytes(1, 2, 'x');
		assertArrayEquals(bytes,
			fixedlenString.encodeRepresentation("01h,02h,\"x\"", mb(false), newset(),
				bytes.length));
	}

	@Test
	public void testGetStringRep_FixedLen() {
		ByteMemBufferImpl buf = mb(false, 'h', 'e', 'l', 'l', 'o', 0, 'a', '\n', 'b', 255, 0);

		// US-ASCII charset doesn't map 0x80-0xff, they result in error characters
		assertEquals("\"hello\\0a\\nb\",FFh",
			fixedlenString.getRepresentation(buf, newset(), buf.getLength()));
	}

	@Test
	public void testEncodeStringRep_FixedLen() throws DataTypeEncodeException {
		byte[] bytes = bytes('h', 'e', 'l', 'l', 'o', 0, 'a', '\n', 'b', 255, 0);
		assertArrayEquals(bytes,
			fixedlenString.encodeRepresentation("\"hello\\0a\\nb\",FFh", mb(false), newset(),
				bytes.length));
	}

	@Test
	public void testGetStringRepEmpty_Term() {
		ByteMemBufferImpl buf = mb(false, 0, 0);

		assertEquals("\"\"", termString.getRepresentation(buf, newset(), buf.getLength()));
	}

	@Test
	public void testEncodeStringRepEmpty_Term() throws DataTypeEncodeException {
		assertArrayEquals(bytes(0), // NOTE: Differs from inverse test above.
			termString.encodeRepresentation("\"\"", mb(false), newset(), -1));
	}

	@Test
	public void testGetStringRepEmpty_TermUTF16() {
		ByteMemBufferImpl buf = mb(false, 0, 0);

		assertEquals("u\"\"", termUtf16String.getRepresentation(buf, newset(), buf.getLength()));
	}

	@Test
	public void testEncodeStringRepEmpty_TermUTF16() throws DataTypeEncodeException {
		assertArrayEquals(bytes(0, 0),
			termUtf16String.encodeRepresentation("u\"\"", mb(false), newset(), -1));
	}

	@Test
	public void testGetStringRepEmpty_FixedLen() {
		ByteMemBufferImpl buf = mb(false, 0, 0, 0, 0, 0);

		assertEquals("\"\"", fixedlenString.getRepresentation(buf, newset(), buf.getLength()));
	}

	@Test
	public void testEncodeStringRepEmpty_FixedLen() throws DataTypeEncodeException {
		// TODO: Should the caller or the encoder handle padding the remaining bytes
		byte[] bytes = bytes(0, 0, 0, 0, 0);
		assertArrayEquals(bytes,
			fixedlenString.encodeRepresentation("\"\"", mb(false), newset(), bytes.length));
	}

	@Test
	public void testGetStringRepEmpty_P() {
		ByteMemBufferImpl buf = mb(false, 0, 0);

		assertEquals("\"\"", pascalString.getRepresentation(buf, newset(), buf.getLength()));
	}

	@Test
	public void testEncodeStringRepEmpty_P() throws DataTypeEncodeException {
		assertArrayEquals(bytes(0, 0),
			pascalString.encodeRepresentation("\"\"", mb(false), newset(), -1));
	}

	@Test
	public void testGetStringRepAllChars() {
		int[] allAsciiChars = new int[256];
		for (int i = 0; i < allAsciiChars.length; i++) {
			allAsciiChars[i] = i;
		}
		ByteMemBufferImpl buf = mb(false, allAsciiChars);

		String actual = fixedlenString.getRepresentation(buf,
			newset().set(StandardCharsets.US_ASCII), buf.getLength());
		//@formatter:off
		String expected =
			"\"\\0\"," +
			"01h,02h,03h,04h,05h,06h,"+
			"\"\\a\\b\\t\\n\\v\\f\\r\",0Eh,0Fh,10h,11h,12h,13h,14h,15h,16h,17h,18h,19h,1Ah,1Bh,1Ch,1Dh,1Eh,1Fh,\""+
			" !\\\"#$%&'()*+,-./0123456789:;<=>?@"+
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\\]^_`"+
			"abcdefghijklmnopqrstuvwxyz{|}~\",7Fh,"+
			"80h,81h,82h,83h,84h,85h,86h,87h,88h,89h,8Ah,8Bh,8Ch,8Dh,8Eh,8Fh,"+
			"90h,91h,92h,93h,94h,95h,96h,97h,98h,99h,9Ah,9Bh,9Ch,9Dh,9Eh,9Fh,"+
			"A0h,A1h,A2h,A3h,A4h,A5h,A6h,A7h,A8h,A9h,AAh,ABh,ACh,ADh,AEh,AFh,"+
			"B0h,B1h,B2h,B3h,B4h,B5h,B6h,B7h,B8h,B9h,BAh,BBh,BCh,BDh,BEh,BFh,"+
			"C0h,C1h,C2h,C3h,C4h,C5h,C6h,C7h,C8h,C9h,CAh,CBh,CCh,CDh,CEh,CFh,"+
			"D0h,D1h,D2h,D3h,D4h,D5h,D6h,D7h,D8h,D9h,DAh,DBh,DCh,DDh,DEh,DFh,"+
			"E0h,E1h,E2h,E3h,E4h,E5h,E6h,E7h,E8h,E9h,EAh,EBh,ECh,EDh,EEh,EFh,"+
			"F0h,F1h,F2h,F3h,F4h,F5h,F6h,F7h,F8h,F9h,FAh,FBh,FCh,FDh,FEh,FFh";
		//@formatter:on

		assertEquals("String rep w/java US-ASCII charset mapping failed", expected, actual);

	}

	@Test
	public void testEncodeStringRepAllChars() throws DataTypeEncodeException {
		byte[] allAsciiChars = new byte[256];
		for (int i = 0; i < allAsciiChars.length; i++) {
			allAsciiChars[i] = (byte) i;
		}
		String repr = "" +
			"\"\\0\"," +
			"01h,02h,03h,04h,05h,06h," +
			"\"\\a\\b\\t\\n\\v\\f\\r\",0Eh,0Fh,10h,11h,12h,13h,14h,15h,16h,17h,18h,19h,1Ah,1Bh,1Ch,1Dh,1Eh,1Fh,\"" +
			" !\\\"#$%&'()*+,-./0123456789:;<=>?@" +
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\\]^_`" +
			"abcdefghijklmnopqrstuvwxyz{|}~\",7Fh," +
			"80h,81h,82h,83h,84h,85h,86h,87h,88h,89h,8Ah,8Bh,8Ch,8Dh,8Eh,8Fh," +
			"90h,91h,92h,93h,94h,95h,96h,97h,98h,99h,9Ah,9Bh,9Ch,9Dh,9Eh,9Fh," +
			"A0h,A1h,A2h,A3h,A4h,A5h,A6h,A7h,A8h,A9h,AAh,ABh,ACh,ADh,AEh,AFh," +
			"B0h,B1h,B2h,B3h,B4h,B5h,B6h,B7h,B8h,B9h,BAh,BBh,BCh,BDh,BEh,BFh," +
			"C0h,C1h,C2h,C3h,C4h,C5h,C6h,C7h,C8h,C9h,CAh,CBh,CCh,CDh,CEh,CFh," +
			"D0h,D1h,D2h,D3h,D4h,D5h,D6h,D7h,D8h,D9h,DAh,DBh,DCh,DDh,DEh,DFh," +
			"E0h,E1h,E2h,E3h,E4h,E5h,E6h,E7h,E8h,E9h,EAh,EBh,ECh,EDh,EEh,EFh," +
			"F0h,F1h,F2h,F3h,F4h,F5h,F6h,F7h,F8h,F9h,FAh,FBh,FCh,FDh,FEh,FFh";

		assertArrayEquals(allAsciiChars, fixedlenString.encodeRepresentation(repr, mb(false),
			newset().set(StandardCharsets.US_ASCII), -1));
	}

	@Test
	public void testGetStringRep_utf16_le() {
		ByteMemBufferImpl buf = mb(false, //
			'h', 0, //
			'e', 0, //
			'l', 0, //
			'l', 0, //
			'o', 0, //
			0, 0, //
			'x', 0, //
			'y', 0);

		assertEquals("u\"hello\\0xy\"",
			fixedUtf16String.getRepresentation(buf, newset(), buf.getLength()));
	}

	@Test
	public void testEncodeStringRep_utf16_le() throws DataTypeEncodeException {
		assertArrayEquals(bytes(
			'h', 0,  //
			'e', 0,  //
			'l', 0,  //
			'l', 0,  //
			'o', 0,  //
			0, 0,  //
			'x', 0, //
			'y', 0),
			fixedUtf16String.encodeRepresentation("U\"hello\\0xy\"", mb(false), newset(), -1));
	}

	@Test
	public void testGetStringRep_utf16_ideographic() {
		// "ab" and 2 random ideographic characters cc01 & 1202 (big & little endian)
		ByteMemBufferImpl buf_be = mb(true, 0, 'a', 0, 'b', 0xcc, 0x01, 0x12, 0x02);
		ByteMemBufferImpl buf_le = mb(false, 'a', 0, 'b', 0, 0x01, 0xcc, 0x02, 0x12);

		String e1 = "u\"ab\ucc01\u1202\"";
		assertEquals(e1, fixedUtf16String.getRepresentation(buf_be, newset(), buf_be.getLength()));
		assertEquals(e1, fixedUtf16String.getRepresentation(buf_le, newset(), buf_le.getLength()));

		String e2_be = "u\"ab\",CCh,01h,12h,02h";
		String e2_le = "u\"ab\",01h,CCh,02h,12h";
		assertEquals(e2_be, fixedUtf16String.getRepresentation(buf_be,
			newset().set(RENDER_ENUM.BYTE_SEQ), buf_be.getLength()));
		assertEquals(e2_le, fixedUtf16String.getRepresentation(buf_le,
			newset().set(RENDER_ENUM.BYTE_SEQ), buf_le.getLength()));

		String e3 = "u\"ab\\uCC01\\u1202\"";
		assertEquals(e3, fixedUtf16String.getRepresentation(buf_be,
			newset().set(RENDER_ENUM.ESC_SEQ), buf_be.getLength()));
		assertEquals(e3, fixedUtf16String.getRepresentation(buf_le,
			newset().set(RENDER_ENUM.ESC_SEQ), buf_le.getLength()));
	}

	@Test
	public void testEncodeStringRep_utf16_ideographic() throws DataTypeEncodeException {
		byte[] bytes_be = bytes(0, 'a', 0, 'b', 0xcc, 0x01, 0x12, 0x02);
		byte[] bytes_le = bytes('a', 0, 'b', 0, 0x01, 0xcc, 0x02, 0x12);

		String e1 = "u\"ab\ucc01\u1202\"";
		assertArrayEquals(bytes_be,
			fixedUtf16String.encodeRepresentation(e1, mb(true), newset(), -1));
		assertArrayEquals(bytes_le,
			fixedUtf16String.encodeRepresentation(e1, mb(false), newset(), -1));

		String e2_be = "u\"ab\",CCh,01h,12h,02h";
		String e2_le = "u\"ab\",01h,CCh,02h,12h";
		assertArrayEquals(bytes_be,
			fixedUtf16String.encodeRepresentation(e2_be, mb(true), newset(), -1));
		assertArrayEquals(bytes_le,
			fixedUtf16String.encodeRepresentation(e2_le, mb(false), newset(), -1));

		String e3 = "u\"ab\\uCC01\\u1202\"";
		assertArrayEquals(bytes_be,
			fixedUtf16String.encodeRepresentation(e3, mb(true), newset(), -1));
		assertArrayEquals(bytes_le,
			fixedUtf16String.encodeRepresentation(e3, mb(false), newset(), -1));
	}

	@Test
	public void testGetStringRep_utf16_escapeseq_U() {
		// 2 utf-16 chars that create a single code point.
		// Should get a 32bit escape seq even though this is 16 bit string.
		ByteMemBufferImpl buf_be = mb(true, 0, 'a', 0, 'b', 0xd8, 0x00, 0xdd, 0x12, 0, 'c');

		assertEquals("u\"ab\\U00010112c\"", fixedUtf16String.getRepresentation(buf_be,
			newset().set(RENDER_ENUM.ESC_SEQ), buf_be.getLength()));
	}

	@Test
	public void testEncodeStringRep_utf16_escapeseq_U() throws DataTypeEncodeException {
		assertArrayEquals(bytes(0, 'a', 0, 'b', 0xd8, 0x00, 0xdd, 0x12, 0, 'c'),
			fixedUtf16String.encodeRepresentation("u\"ab\\U00010112c\"", mb(true), newset(), -1));
	}

	@Test
	public void testGetStringRep_utf32() {
		ByteMemBufferImpl buf = mb(false, //
			'h', 0, 0, 0, //
			'e', 0, 0, 0, //
			'l', 0, 0, 0, //
			'l', 0, 0, 0, //
			'o', 0, 0, 0, //
			0, 0, 0, 0, //
			'x', 0, 0, 0, //
			'y', 0, 0, 0);

		assertEquals("U\"hello\\0xy\"",
			fixedUtf32String.getRepresentation(buf, newset(), buf.getLength()));
	}

	@Test
	public void testEncodeStringRep_utf32() throws DataTypeEncodeException {
		assertArrayEquals(bytes(
			'h', 0, 0, 0, //
			'e', 0, 0, 0, //
			'l', 0, 0, 0, //
			'l', 0, 0, 0, //
			'o', 0, 0, 0, //
			0, 0, 0, 0, //
			'x', 0, 0, 0, //
			'y', 0, 0, 0),
			fixedUtf32String.encodeRepresentation("U\"hello\\0xy\"", mb(false), newset(), -1));
	}

	@Test
	public void testGetStringRep_Pascal_EOF() {
		assertEquals("Pascal string with length past end of mem should return error... string",
			"??...",
			pascal255String.getRepresentation(mb(false, 5, 'h', 'e', 'l', 'l'), newset(), 5));

	}

	//-------------------------------------------------------------------------------------
	// StringDataInstance.isMissingNullTerminator()
	//-------------------------------------------------------------------------------------

	@Test
	public void testHasNullTerm() {
		ByteMemBufferImpl buf = mb(false, 'a', 'b', 0);

		assertFalse(mkSDI(termString, buf, newset(), buf.getLength()).isMissingNullTerminator());
	}

	@Test
	public void testHasNullTermEOF() {
		ByteMemBufferImpl buf = mb(false, 'a', 'b');

		assertTrue(mkSDI(termString, buf, newset(), buf.getLength()).isMissingNullTerminator());
	}

	@Test
	public void testHasNullTermUTF16() {
		ByteMemBufferImpl buf = mb(false, 'a', 0, 'b', 0, 0, 0);

		assertFalse(
			mkSDI(termUtf16String, buf, newset(), buf.getLength()).isMissingNullTerminator());
	}

	@Test
	public void testHasNullTermFixed() {
		ByteMemBufferImpl buf = mb(false, 'a', 'b', 'c', 0, 0, 0);

		assertTrue(mkSDI(fixedlenString, buf, newset(), 2).isMissingNullTerminator());
		assertTrue(mkSDI(fixedlenString, buf, newset(), 3).isMissingNullTerminator());
		assertFalse(mkSDI(fixedlenString, buf, newset(), 4).isMissingNullTerminator());
	}

	@Test
	public void testHasNullTermFixedUTF16() {
		ByteMemBufferImpl buf = mb(false, 'a', 0, 'b', 0, 'c', 0, 0, 0, 0, 0);

		assertTrue(mkSDI(fixedUtf16String, buf, newset(), 4).isMissingNullTerminator());
		assertTrue(mkSDI(fixedUtf16String, buf, newset(), 6).isMissingNullTerminator());
		assertFalse(mkSDI(fixedUtf16String, buf, newset(), 8).isMissingNullTerminator());
	}
}
