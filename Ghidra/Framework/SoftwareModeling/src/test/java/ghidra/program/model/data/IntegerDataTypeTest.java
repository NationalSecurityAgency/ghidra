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

import generic.test.AbstractGenericTest;
import ghidra.docking.settings.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;

public class IntegerDataTypeTest extends AbstractGenericTest {

	private static MemBuffer buf(boolean bigEndian, int... vals) {
		return new ByteMemBufferImpl(Address.NO_ADDRESS, bytes(vals), bigEndian);
	}

	private static Settings format(FormatSettingsDefinition setDef) {
		Settings settings = new SettingsImpl();
		setDef.setChoice(settings, setDef.getChoice(null));
		return settings;
	}

	// NB. Need at least one byte to appear "initialized"
	private static final MemBuffer BE = buf(true, 0);
	private static final MemBuffer LE = buf(false, 0);

	private static final Settings HEX = format(FormatSettingsDefinition.DEF_HEX);
	private static final Settings DEC = format(FormatSettingsDefinition.DEF_DECIMAL);
	private static final Settings BIN = format(FormatSettingsDefinition.DEF_BINARY);
	private static final Settings OCT = format(FormatSettingsDefinition.DEF_OCTAL);
	private static final Settings CHR = format(FormatSettingsDefinition.DEF_CHAR);

	private interface EncodeRunnable {
		void run() throws Exception;
	}

	private static void assertFails(EncodeRunnable r) throws Exception {
		try {
			r.run();
		}
		catch (DataTypeEncodeException e) {
			return; // pass
		}
		fail();
	}

	@Test
	public void testEncodeValueUnsignedByteBE() throws Exception {
		DataType type = AbstractIntegerDataType.getUnsignedDataType(1, null);

		// Technically, these two are exactly the same test, just different Java syntax
		assertArrayEquals(bytes(0xff), type.encodeValue((byte) 0xff, BE, HEX, 1));
		assertArrayEquals(bytes(0xff), type.encodeValue((byte) -1, BE, HEX, 1));

		assertFails(() -> type.encodeValue((short) 0x100, BE, HEX, 1));
		assertFails(() -> type.encodeValue((short) -1, BE, HEX, 1));

		assertArrayEquals(bytes(0xff), type.encodeValue(0xff, BE, HEX, 1));
		// This fails, because (int)-1 is 4294967295 when treated unsigned
		assertFails(() -> type.encodeValue(-1, BE, HEX, 1));
	}

	@Test
	public void testEncodeRepresentationUnsignedByteHexBE() throws Exception {
		DataType type = AbstractIntegerDataType.getUnsignedDataType(1, null);

		// Sanity check: Renders unsigned
		assertEquals("80h", type.getRepresentation(buf(true, 0x80), HEX, 1));

		assertArrayEquals(bytes(0x00), type.encodeRepresentation("0h", BE, HEX, 1));
		assertArrayEquals(bytes(0x7f), type.encodeRepresentation("7fh", BE, HEX, 1));
		assertArrayEquals(bytes(0x80), type.encodeRepresentation("80h", BE, HEX, 1));
		assertArrayEquals(bytes(0xff), type.encodeRepresentation("ffh", BE, HEX, 1));

		assertFails(() -> type.encodeRepresentation("100h", BE, HEX, 1));
		assertFails(() -> type.encodeRepresentation("-1h", BE, HEX, 1));
	}

	@Test
	public void testEncodeRepresentationSignedShortHexBE() throws Exception {
		DataType type = AbstractIntegerDataType.getSignedDataType(2, null);

		// Sanity check: Negative hex values render unsigned
		assertEquals("8000h", type.getRepresentation(buf(true, 0x80, 0x00), HEX, 2));

		assertArrayEquals(bytes(0x00, 0x00), type.encodeRepresentation("0h", BE, HEX, 2));
		assertArrayEquals(bytes(0x7f, 0xff), type.encodeRepresentation("7fffh", BE, HEX, 2));
		assertArrayEquals(bytes(0x80, 0x00), type.encodeRepresentation("8000h", BE, HEX, 2));
		assertArrayEquals(bytes(0xff, 0xff), type.encodeRepresentation("ffffh", BE, HEX, 2));

		assertArrayEquals(bytes(0xff, 0xff), type.encodeRepresentation("-1h", BE, HEX, 2));
		assertArrayEquals(bytes(0x80, 0x00), type.encodeRepresentation("-8000h", BE, HEX, 2));

		assertFails(() -> type.encodeRepresentation("10000h", BE, HEX, 2));
		assertFails(() -> type.encodeRepresentation("-8001h", BE, HEX, 2));
	}

	@Test
	public void testEncodeRepresentationSignedShortHexLE() throws Exception {
		DataType type = AbstractIntegerDataType.getSignedDataType(2, null);

		// Sanity check: Negative hex values render unsigned
		assertEquals("8000h", type.getRepresentation(buf(false, 0x00, 0x80), HEX, 2));

		assertArrayEquals(bytes(0x00, 0x00), type.encodeRepresentation("0h", LE, HEX, 2));
		assertArrayEquals(bytes(0xff, 0x7f), type.encodeRepresentation("7fffh", LE, HEX, 2));
		assertArrayEquals(bytes(0x00, 0x80), type.encodeRepresentation("8000h", LE, HEX, 2));
		assertArrayEquals(bytes(0xff, 0xff), type.encodeRepresentation("ffffh", LE, HEX, 2));

		assertArrayEquals(bytes(0xff, 0xff), type.encodeRepresentation("-1h", LE, HEX, 2));
		assertArrayEquals(bytes(0x00, 0x80), type.encodeRepresentation("-8000h", LE, HEX, 2));

		assertFails(() -> type.encodeRepresentation("10000h", LE, HEX, 2));
		assertFails(() -> type.encodeRepresentation("-8001h", LE, HEX, 2));
	}

	@Test
	public void testEncodeRepresentationUnsignedShortHexBE() throws Exception {
		DataType type = AbstractIntegerDataType.getUnsignedDataType(2, null);

		// Sanity check: Renders unsigned
		assertEquals("8000h", type.getRepresentation(buf(true, 0x80, 0x00), HEX, 2));

		assertArrayEquals(bytes(0x00, 0x00), type.encodeRepresentation("0h", BE, HEX, 2));
		assertArrayEquals(bytes(0x7f, 0xff), type.encodeRepresentation("7fffh", BE, HEX, 2));
		assertArrayEquals(bytes(0x80, 0x00), type.encodeRepresentation("8000h", BE, HEX, 2));
		assertArrayEquals(bytes(0xff, 0xff), type.encodeRepresentation("ffffh", BE, HEX, 2));

		assertFails(() -> type.encodeRepresentation("-1h", BE, HEX, 2));
		assertFails(() -> type.encodeRepresentation("-8000h", BE, HEX, 2));
		assertFails(() -> type.encodeRepresentation("10000h", BE, HEX, 2));
		assertFails(() -> type.encodeRepresentation("-8001h", BE, HEX, 2));
	}

	@Test
	public void testEncodeRepresentationSignedShortDecBE() throws Exception {
		DataType type = AbstractIntegerDataType.getSignedDataType(2, null);

		// Sanity check: Negative hex values render signed
		assertEquals("-32768", type.getRepresentation(buf(true, 0x80, 0x00), DEC, 2));

		assertArrayEquals(bytes(0x00, 0x00), type.encodeRepresentation("0", BE, DEC, 2));
		assertArrayEquals(bytes(0x7f, 0xff), type.encodeRepresentation("32767", BE, DEC, 2));
		assertArrayEquals(bytes(0x80, 0x00), type.encodeRepresentation("-32768", BE, DEC, 2));
		assertArrayEquals(bytes(0xff, 0xff), type.encodeRepresentation("-1", BE, DEC, 2));

		assertFails(() -> type.encodeRepresentation("32768", BE, DEC, 2));
		assertFails(() -> type.encodeRepresentation("-32769", BE, DEC, 2));
	}

	@Test
	public void testEncodeRepresentationUnsignedShortDecBE() throws Exception {
		DataType type = AbstractIntegerDataType.getUnsignedDataType(2, null);

		// Sanity check: Renders unsigned
		assertEquals("32768", type.getRepresentation(buf(true, 0x80, 0x00), DEC, 2));

		assertArrayEquals(bytes(0x00, 0x00), type.encodeRepresentation("0", BE, DEC, 2));
		assertArrayEquals(bytes(0x7f, 0xff), type.encodeRepresentation("32767", BE, DEC, 2));
		assertArrayEquals(bytes(0x80, 0x00), type.encodeRepresentation("32768", BE, DEC, 2));
		assertArrayEquals(bytes(0xff, 0xff), type.encodeRepresentation("65535", BE, DEC, 2));

		assertFails(() -> type.encodeRepresentation("-1", BE, DEC, 2));
		assertFails(() -> type.encodeRepresentation("65536", BE, DEC, 2));
	}

	@Test
	public void testEncodeRepresentationSignedShortBinBE() throws Exception {
		DataType type = AbstractIntegerDataType.getUnsignedDataType(2, null);

		// Sanity check
		assertEquals("100000011b", type.getRepresentation(buf(true, 0x01, 0x03), BIN, 2));

		assertArrayEquals(bytes(0x01, 0x03), type.encodeRepresentation("100000011b", BE, BIN, 2));
	}

	@Test
	public void testEncodeRepresentationSignedShortOctBE() throws Exception {
		DataType type = AbstractIntegerDataType.getUnsignedDataType(2, null);

		// Sanity check
		assertEquals("403o", type.getRepresentation(buf(true, 0x01, 0x03), OCT, 2));

		assertArrayEquals(bytes(0x01, 0x03), type.encodeRepresentation("403o", BE, OCT, 2));
	}

	@Test
	public void testEncodeRepresentationChar() throws Exception {
		DataType stype = AbstractIntegerDataType.getSignedDataType(1, null);
		DataType utype = AbstractIntegerDataType.getUnsignedDataType(1, null);

		// Sanity check
		assertEquals("'A'", stype.getRepresentation(buf(true, 0x41), CHR, 1));
		assertEquals("'A'", utype.getRepresentation(buf(true, 0x41), CHR, 1));

		assertArrayEquals(bytes(0x41), stype.encodeRepresentation("'A'", BE, CHR, 1));
		assertArrayEquals(bytes(0x41), utype.encodeRepresentation("'A'", BE, CHR, 1));
	}
}
