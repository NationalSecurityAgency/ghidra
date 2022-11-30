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

import java.nio.charset.Charset;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.LittleEndianDataConverter;

public class DialogResourceDataTypeTest extends AbstractGTest {

	private GenericAddressSpace addressSpace;

	@Before
	public void setUp() {
		addressSpace = new GenericAddressSpace("Test Address Space", 32, AddressSpace.TYPE_RAM, 1);
	}

	@Test
	public void testDlgTemplate() throws MemoryAccessException {
		byte[] dialogTemplate = getDlgTemplateResource();
		MemBuffer mb = new ByteMemBufferImpl(addressSpace.getAddress(0), dialogTemplate, false);
		DialogResourceDataType dr = new DialogResourceDataType();
		DataTypeComponent[] components = dr.getAllComponents(mb);
		assertEquals(6, components.length);

		DataTypeComponent titleComponent = components[3];
		assertEquals("Dialog Title", titleComponent.getFieldName());
		byte[] titleBytes = new byte[titleComponent.getLength() - 2]; // cut off the null terminator
		mb.getBytes(titleBytes, titleComponent.getOffset());
		String title = new String(titleBytes, Charset.forName("UTF-16LE"));
		assertEquals("Test Dialog", title);

		DataTypeComponent sizeComponent = components[4];
		assertEquals("Dialog Font Size", sizeComponent.getFieldName());
		assertEquals(8, mb.getShort(sizeComponent.getOffset()));

		DataTypeComponent typefaceComponent = components[5];
		assertEquals("Dialog Font Typeface", typefaceComponent.getFieldName());
		byte[] typefaceBytes = new byte[typefaceComponent.getLength() - 2]; // cut off the null terminator
		mb.getBytes(typefaceBytes, typefaceComponent.getOffset());
		String typeface = new String(typefaceBytes, Charset.forName("UTF-16LE"));
		assertEquals("Test Typeface", typeface);
	}

	@Test
	public void testDlgTemplateEx() throws MemoryAccessException {
		byte[] dialogTemplateEx = getDlgTemplateExResource();
		MemBuffer mb = new ByteMemBufferImpl(addressSpace.getAddress(0), dialogTemplateEx, false);
		DialogResourceDataType dr = new DialogResourceDataType();
		DataTypeComponent[] components = dr.getAllComponents(mb);
		assertEquals(9, components.length);

		DataTypeComponent titleComponent = components[3];
		assertEquals("Dialog Title", titleComponent.getFieldName());
		byte[] titleBytes = new byte[titleComponent.getLength() - 2]; // cut off the null terminator
		mb.getBytes(titleBytes, titleComponent.getOffset());
		String title = new String(titleBytes, Charset.forName("UTF-16LE"));
		assertEquals("Test Dialog", title);

		DataTypeComponent sizeComponent = components[4];
		assertEquals("Dialog Font Size", sizeComponent.getFieldName());
		assertEquals(8, mb.getShort(sizeComponent.getOffset()));

		DataTypeComponent weightComponent = components[5];
		assertEquals("Dialog Font Weight", weightComponent.getFieldName());
		assertEquals(400, mb.getShort(weightComponent.getOffset()));

		DataTypeComponent italicComponent = components[6];
		assertEquals("Dialog Font Italic", italicComponent.getFieldName());
		assertEquals(0, mb.getByte(italicComponent.getOffset()));

		DataTypeComponent charsetComponent = components[7];
		assertEquals("Dialog Font Charset", charsetComponent.getFieldName());
		assertEquals(1, mb.getByte(charsetComponent.getOffset()));

		DataTypeComponent typefaceComponent = components[8];
		assertEquals("Dialog Font Typeface", typefaceComponent.getFieldName());
		byte[] typefaceBytes = new byte[typefaceComponent.getLength() - 2]; // cut off the null terminator
		mb.getBytes(typefaceBytes, typefaceComponent.getOffset());
		String typeface = new String(typefaceBytes, Charset.forName("UTF-16LE"));
		assertEquals("Test Typeface", typeface);
	}

	private byte[] getDlgTemplateExResource() {
		byte[] resourceBytes = new byte[88];
		LittleEndianDataConverter leConverter = LittleEndianDataConverter.INSTANCE;

		// @formatter:off
		leConverter.putShort(resourceBytes,  0,    (short)  1); // dlgVer, must be 1
		leConverter.putShort(resourceBytes,  2,    (short) -1); // signature, must be 0xffff
		leConverter.putInt(  resourceBytes,  4,             0); // helpID
		leConverter.putInt(  resourceBytes,  8,             0); // exStyle
		leConverter.putInt(  resourceBytes, 12,          0x40); // style: DS_SETFONT
		leConverter.putShort(resourceBytes, 16,    (short)  0); // cDlgItems (none)
		leConverter.putShort(resourceBytes, 18,    (short)  0); // x
		leConverter.putShort(resourceBytes, 20,    (short)  0); // y
		leConverter.putShort(resourceBytes, 22, (short)  0xd0); // cx
		leConverter.putShort(resourceBytes, 24, (short)  0xd0); // cy
		leConverter.putShort(resourceBytes, 26,     (short) 0); // menu: (none)
		leConverter.putShort(resourceBytes, 28,     (short) 0); // windowClass: (predefined dialog box class)
		leConverter.putShort(resourceBytes, 30,  (short) 0x54); // title: "Test Dialog"
		leConverter.putShort(resourceBytes, 32,  (short) 0x65);
		leConverter.putShort(resourceBytes, 34,  (short) 0x73);
		leConverter.putShort(resourceBytes, 36,  (short) 0x74);
		leConverter.putShort(resourceBytes, 38,  (short) 0x20);
		leConverter.putShort(resourceBytes, 40,  (short) 0x44);
		leConverter.putShort(resourceBytes, 42,  (short) 0x69);
		leConverter.putShort(resourceBytes, 44,  (short) 0x61);
		leConverter.putShort(resourceBytes, 46,  (short) 0x6c);
		leConverter.putShort(resourceBytes, 48,  (short) 0x6f);
		leConverter.putShort(resourceBytes, 50,  (short) 0x67);
		leConverter.putShort(resourceBytes, 52,  (short)  0x0);

		// optional font fields, present here because DS_SETFONT was used
		leConverter.putShort(resourceBytes, 54,  (short)    8); // pointsize
		leConverter.putShort(resourceBytes, 56,  (short)  400); // weight: FW_NORMAL
		resourceBytes[58] =                                 0;  // italic: FALSE
		resourceBytes[59] =                          (byte) 1;  // charset: DEFAULT_CHARSET
		leConverter.putShort(resourceBytes, 60,  (short) 0x54); // typeface: "Test Typeface"
		leConverter.putShort(resourceBytes, 62,  (short) 0x65);
		leConverter.putShort(resourceBytes, 64,  (short) 0x73);
		leConverter.putShort(resourceBytes, 66,  (short) 0x74);
		leConverter.putShort(resourceBytes, 68,  (short) 0x20);
		leConverter.putShort(resourceBytes, 70,  (short) 0x54);
		leConverter.putShort(resourceBytes, 72,  (short) 0x79);
		leConverter.putShort(resourceBytes, 74,  (short) 0x70);
		leConverter.putShort(resourceBytes, 76,  (short) 0x65);
		leConverter.putShort(resourceBytes, 78,  (short) 0x66);
		leConverter.putShort(resourceBytes, 80,  (short) 0x61);
		leConverter.putShort(resourceBytes, 82,  (short) 0x63);
		leConverter.putShort(resourceBytes, 84,  (short) 0x65);
		leConverter.putShort(resourceBytes, 86,  (short)  0x0);
		// @formatter:on

		return resourceBytes;
	}

	private byte[] getDlgTemplateResource() {
		byte[] resourceBytes = new byte[76];
		LittleEndianDataConverter leConverter = LittleEndianDataConverter.INSTANCE;

		// @formatter:off
		leConverter.putInt(  resourceBytes,  0,          0x40); // style: DS_SETFONT
		leConverter.putInt(  resourceBytes,  4,             0); // exStyle
		leConverter.putShort(resourceBytes,  8,    (short)  0); // cdit (none)
		leConverter.putShort(resourceBytes, 10,    (short)  0); // x
		leConverter.putShort(resourceBytes, 12,    (short)  0); // y
		leConverter.putShort(resourceBytes, 14, (short)  0xd0); // cx
		leConverter.putShort(resourceBytes, 16, (short)  0xd0); // cy
		leConverter.putShort(resourceBytes, 18,     (short) 0); // menu: (none)
		leConverter.putShort(resourceBytes, 20,     (short) 0); // windowClass: (predefined dialog box class)
		leConverter.putShort(resourceBytes, 22,  (short) 0x54); // title: "Test Dialog"
		leConverter.putShort(resourceBytes, 24,  (short) 0x65);
		leConverter.putShort(resourceBytes, 26,  (short) 0x73);
		leConverter.putShort(resourceBytes, 28,  (short) 0x74);
		leConverter.putShort(resourceBytes, 30,  (short) 0x20);
		leConverter.putShort(resourceBytes, 32,  (short) 0x44);
		leConverter.putShort(resourceBytes, 34,  (short) 0x69);
		leConverter.putShort(resourceBytes, 36,  (short) 0x61);
		leConverter.putShort(resourceBytes, 38,  (short) 0x6c);
		leConverter.putShort(resourceBytes, 40,  (short) 0x6f);
		leConverter.putShort(resourceBytes, 42,  (short) 0x67);
		leConverter.putShort(resourceBytes, 44,  (short)  0x0);

		// optional font fields, present here because DS_SETFONT was used
		leConverter.putShort(resourceBytes, 46,  (short)    8); // pointsize
		leConverter.putShort(resourceBytes, 48,  (short) 0x54); // typeface: "Test Typeface"
		leConverter.putShort(resourceBytes, 50,  (short) 0x65);
		leConverter.putShort(resourceBytes, 52,  (short) 0x73);
		leConverter.putShort(resourceBytes, 54,  (short) 0x74);
		leConverter.putShort(resourceBytes, 56,  (short) 0x20);
		leConverter.putShort(resourceBytes, 58,  (short) 0x54);
		leConverter.putShort(resourceBytes, 60,  (short) 0x79);
		leConverter.putShort(resourceBytes, 62,  (short) 0x70);
		leConverter.putShort(resourceBytes, 64,  (short) 0x65);
		leConverter.putShort(resourceBytes, 66,  (short) 0x66);
		leConverter.putShort(resourceBytes, 68,  (short) 0x61);
		leConverter.putShort(resourceBytes, 70,  (short) 0x63);
		leConverter.putShort(resourceBytes, 72,  (short) 0x65);
		leConverter.putShort(resourceBytes, 74,  (short)  0x0);
		// @formatter:on

		return resourceBytes;
	}
}
