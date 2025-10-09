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
package ghidra.app.util.bin.format.dwarf.attribs;

import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.*;
import static ghidra.app.util.bin.format.dwarf.attribs.DWARFForm.*;
import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf.DWARFSourceLanguage;
import ghidra.app.util.bin.format.dwarf.DWARFTestBase;
import ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.AttrDef;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;

/**
 * Test reading binary representations of DWARF attributes from raw bytes.
 */
public class DWARFAttributeFactoryTest extends DWARFTestBase {

	@Override
	public ProgramDB createProgram() throws Exception {
		return createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY64_BE, this);
	}

	private DWARFAttributeValue read(BinaryReader br, DWARFAttribute attr, DWARFForm form)
			throws IOException {
		ensureCompUnit();
		AttrDef spec = new AttrDef(attr, attr.getId(), form, 0);
		DWARFFormContext context = new DWARFFormContext(br, cu, spec);
		DWARFAttributeValue val = form.readValue(context);
		return val;
	}

	@Test
	public void testStr() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			/* str1 */ 'a', 'b', 0,
			/* str2 */ 'c', 0,
			/* str3 */ 'x', 'y', '\n', 0,
			/* guard byte for test */ 0xff);
		// @formatter:on
		DWARFAttributeValue result = read(br, DW_AT_name, DW_FORM_string);
		assertTrue("Should be string", result instanceof DWARFStringAttribute);
		assertEquals("ab", ((DWARFStringAttribute) result).getValue(null));

		result = read(br, DW_AT_name, DW_FORM_string);
		assertTrue("Should be string", result instanceof DWARFStringAttribute);
		assertEquals("c", ((DWARFStringAttribute) result).getValue(null));

		result = read(br, DW_AT_name, DW_FORM_string);
		assertTrue("Should be string", result instanceof DWARFStringAttribute);
		assertEquals("Test reading nullterm string with non-printable chars", "xy\n",
			((DWARFStringAttribute) result).getValue(null));

		assertEquals("guard byte", (byte) 0xff, br.readNextByte());
	}

	@Test
	public void testStrp_32() throws IOException {
		stringTable.add(1, "string1 at 1");
		stringTable.add(100, "string2 at 100");

		// @formatter:off
		BinaryReader br = br(
			/* ref to str2 */ 0, 0, 0, 100,
			/* ref to str1 */ 0, 0, 0, 1,
			/* ref to str2 ofcut */ 0, 0, 0, 101,
			/* guard byte for test */ 0xff);
		// @formatter:on

		DWARFAttributeValue result = read(br, DW_AT_name, DW_FORM_strp);
		assertTrue("Should be string", result instanceof DWARFStringAttribute);
		assertEquals("string2 at 100", ((DWARFStringAttribute) result).getValue(cu));

		result = read(br, DW_AT_name, DW_FORM_strp);
		assertTrue("Should be string", result instanceof DWARFStringAttribute);
		assertEquals("string1 at 1", ((DWARFStringAttribute) result).getValue(cu));

		// test string ref to substring of string2
		result = read(br, DW_AT_name, DW_FORM_strp);
		assertTrue("Should be string", result instanceof DWARFStringAttribute);
		assertEquals("tring2 at 100", ((DWARFStringAttribute) result).getValue(cu));

		assertEquals("guard byte", (byte) 0xff, br.readNextByte());
	}

	@Test
	public void testStrp_64() throws IOException {
		stringTable.add(1, "string1 at 1");
		stringTable.add(100, "string2 at 100");

		// @formatter:off
		BinaryReader br = br(
			/* str1 */ 0, 0, 0, 0, 0, 0, 0, 100,
			/* str2 */ 0, 0, 0, 0, 0, 0, 0, 1,
			/* guard byte for test */ 0xff);
		// @formatter:on

		setCompUnit(dwarfProg.addCompUnit(DWARFSourceLanguage.DW_LANG_C, 8 /* dwarf64 */));

		DWARFAttributeValue result1 = read(br, DW_AT_name, DW_FORM_strp);
		assertTrue("Should be string", result1 instanceof DWARFStringAttribute);
		assertEquals("string2 at 100", ((DWARFStringAttribute) result1).getValue(cu));

		DWARFAttributeValue result2 = read(br, DW_AT_name, DW_FORM_strp);
		assertTrue("Should be string", result2 instanceof DWARFStringAttribute);
		assertEquals("string1 at 1", ((DWARFStringAttribute) result2).getValue(cu));

		assertEquals("guard byte", (byte) 0xff, br.readNextByte());
	}

	@Test
	public void testData1() throws IOException {
		BinaryReader br = br(55, 0xfe);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_data1);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_data1);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be -2", -2, ((DWARFNumericAttribute) result).getValue());
		assertEquals("should be fe", 0xfe, ((DWARFNumericAttribute) result).getUnsignedValue());
	}

	@Test
	public void testData2() throws IOException {
		BinaryReader br = br(0, 55, 0xff, 0xfe);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_data2);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_data2);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be -2", -2, ((DWARFNumericAttribute) result).getValue());
		assertEquals("should be fffe", 0xfffe, ((DWARFNumericAttribute) result).getUnsignedValue());
	}

	@Test
	public void testData4() throws IOException {
		BinaryReader br = br(0, 0, 0, 55, 0xff, 0xff, 0xff, 0xfe);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_data4);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_data4);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be -2", -2, ((DWARFNumericAttribute) result).getValue());
		assertEquals("should be 0xfffffffe", 0xffff_fffeL,
			((DWARFNumericAttribute) result).getUnsignedValue());
	}

	@Test
	public void testData8() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			0, 0, 0, 0, 0, 0, 0, 55,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe);
		// @formatter:on

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_data8);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_data8);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		// these next two asserts are probably the same test as there isn't a way to
		// simulate unsigned long values
		assertEquals("should be -2", -2, ((DWARFNumericAttribute) result).getValue());
		assertEquals("should be 0xfffffffffffffffe", 0xffff_ffff_ffff_fffeL,
			((DWARFNumericAttribute) result).getUnsignedValue());
	}

	@Test
	public void testSData() throws IOException {
		BinaryReader br = br(0, 55, 0xff, 0x7e);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_sdata);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 0", 0, ((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_sdata);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_sdata);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be -129", -129, ((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testUData() throws IOException {
		BinaryReader br = br(0, 55, 0xff, 0x7e);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_udata);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 0", 0, ((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_udata);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_udata);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 16255", 16255, ((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testAddr() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			0, 0, 0, 0, 0, 0, 0, 55,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe);
		// @formatter:on

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_addr);
		assertTrue("Should be addr", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getUnsignedValue());

		result = read(br, DW_AT_byte_size, DW_FORM_addr);
		assertTrue("Should be addr", result instanceof DWARFNumericAttribute);
		assertEquals("should be feffffffffffffff", 0xfffffffffffffffeL,
			((DWARFNumericAttribute) result).getUnsignedValue());
	}

	@Test
	public void testBlock1() throws IOException {
		BinaryReader br = br(1, 0x55, 0);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_block1);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 1", 1, ((DWARFBlobAttribute) result).getLength());
		assertEquals("should be 0x55", 0x55, ((DWARFBlobAttribute) result).getBytes()[0]);

		result = read(br, DW_AT_byte_size, DW_FORM_block1);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 0", 0, ((DWARFBlobAttribute) result).getLength());

		int[] bytes = new int[1 + 255 /* max_ubyte */];
		bytes[0] = 0xff;
		result = read(br(bytes), DW_AT_byte_size, DW_FORM_block1);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 255", 255, ((DWARFBlobAttribute) result).getLength());
	}

	@Test
	public void testBlock2() throws IOException {
		BinaryReader br = br(0, 1, 0x55, 0, 0);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_block2);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 1", 1, ((DWARFBlobAttribute) result).getLength());
		assertEquals("should be 0x55", 0x55, ((DWARFBlobAttribute) result).getBytes()[0]);

		result = read(br, DW_AT_byte_size, DW_FORM_block1);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 0", 0, ((DWARFBlobAttribute) result).getLength());

		int[] bytes = new int[2 + 0xffff /* max_ushort */];
		bytes[0] = 0xff;
		bytes[1] = 0xff;
		result = read(br(bytes), DW_AT_byte_size, DW_FORM_block2);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 64k", 0xffff, ((DWARFBlobAttribute) result).getLength());
	}

	@Test
	public void testBlock4() throws IOException {
		BinaryReader br = br(0, 0, 0, 1, 0x55, 0, 0, 0, 0);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_block4);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 1", 1, ((DWARFBlobAttribute) result).getLength());
		assertEquals("should be 0x55", 0x55, ((DWARFBlobAttribute) result).getBytes()[0]);

		result = read(br, DW_AT_byte_size, DW_FORM_block4);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 0", 0, ((DWARFBlobAttribute) result).getLength());

		// Test max block4 sized chunk
		int[] bytes = new int[4 + DWARFForm.MAX_BLOCK4_SIZE];
		//DWARFAttributeFactory.MAX_BLOCK4_SIZE == 0x00_10_00_00
		bytes[0] = 0x00;
		bytes[1] = 0x10;
		bytes[2] = 0x00;
		bytes[3] = 0x00;
		result = read(br(bytes), DW_AT_byte_size, DW_FORM_block4);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be MAX_BLOCK4_SIZE", DWARFForm.MAX_BLOCK4_SIZE,
			((DWARFBlobAttribute) result).getLength());

		// Test block4 size that is larger than max
		bytes = new int[4 + DWARFForm.MAX_BLOCK4_SIZE + 1];
		//DWARFAttributeFactory.MAX_BLOCK4_SIZE == 0x00_10_00_00 + 1 == 0x00_10_00_01
		bytes[0] = 0x00;
		bytes[1] = 0x10;
		bytes[2] = 0x00;
		bytes[3] = 0x01;
		try {
			result = read(br(bytes), DW_AT_byte_size, DW_FORM_block4);
			fail(
				"Should not get here, dw_form_block4 size should have been larger than max sanity check");
		}
		catch (IOException ioe) {
			// good
		}
	}

	@Test
	public void testBlock() throws IOException {
		BinaryReader br = br(1, 0x55, 0);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_block);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 1", 1, ((DWARFBlobAttribute) result).getLength());
		assertEquals("should be 0x55", 0x55, ((DWARFBlobAttribute) result).getBytes()[0]);

		result = read(br, DW_AT_byte_size, DW_FORM_block);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 0", 0, ((DWARFBlobAttribute) result).getLength());
	}

	@Test
	public void testExprLoc() throws IOException {
		BinaryReader br = br(1, 0x55, 0);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_exprloc);
		assertTrue("Should be exprloc", result instanceof DWARFBlobAttribute);
		assertEquals("should be 1", 1, ((DWARFBlobAttribute) result).getLength());
		assertEquals("should be 0x55", 0x55, ((DWARFBlobAttribute) result).getBytes()[0]);

		result = read(br, DW_AT_byte_size, DW_FORM_exprloc);
		assertTrue("Should be exprloc", result instanceof DWARFBlobAttribute);
		assertEquals("should be 0", 0, ((DWARFBlobAttribute) result).getLength());
	}

	@Test
	public void testFlag() throws IOException {
		BinaryReader br = br(55, 0x00);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_flag);
		assertTrue("Should be flag", result instanceof DWARFBooleanAttribute);
		assertEquals("should be true", true, ((DWARFBooleanAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_flag);
		assertTrue("Should be flag", result instanceof DWARFBooleanAttribute);
		assertEquals("should be false", false, ((DWARFBooleanAttribute) result).getValue());
	}

	@Test
	public void testFlagPresent() throws IOException {
		BinaryReader br = br(new int[] {} /* no bytes needed for flag_present */);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_flag_present);
		assertTrue("Should be flag", result instanceof DWARFBooleanAttribute);
		assertEquals("should be true", true, ((DWARFBooleanAttribute) result).getValue());
	}

	@Test
	public void testRef1() throws IOException {
		BinaryReader br = br(55, 0xfe);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_ref1);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55 + cuOffset", 55 + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_ref1);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be fe + cuOffset", 0xfe + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testRef2() throws IOException {
		BinaryReader br = br(0, 55, 0xff, 0xfe);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_ref2);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55 + cuOffset", 55 + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_ref2);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be fffe + cuOffset", 0xfffe + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testRef4() throws IOException {
		BinaryReader br = br(0, 0, 0, 55, 0xff, 0xff, 0xff, 0xfe);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_ref4);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55 + cuOffset", 55 + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_ref4);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be fffffffe + cuOffset", 0xff_ff_ff_feL + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testSecOffset() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			0, 0, 0, 55,
			0, 0, 0, 0, 0, 0, 0, 56
		);
		// @formatter:on

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_sec_offset);
		assertTrue("Should be ptr", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		addCompUnit64();
		result = read(br, DW_AT_byte_size, DW_FORM_sec_offset);
		assertTrue("Should be ptr", result instanceof DWARFNumericAttribute);
		assertEquals("should be 56", 56, ((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testRef8() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			0, 0, 0, 0, 0, 0, 0, 55,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe);
		// @formatter:on

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_ref8);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55 + cuOffset", 55 + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_ref8);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be fffffffffffffffe + cuOffset",
			0xff_ff_ff_ff_ff_ff_ff_feL + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testRefUData() throws IOException {
		BinaryReader br = br(55, 0xff, 0x7e);

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_ref_udata);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55 + cuOffset", 55 + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_ref_udata);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 0x3f7f + cuOffset", 0x3f7f + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testRefAddr() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			0, 0, 0, 55,
			0xff, 0xff, 0xff, 0xff,
			0, 0, 0, 0, 0, 0, 0, 55,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe
			);
		// @formatter:on

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_ref_addr);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_ref_addr);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be ffffffff", 0xff_ff_ff_ffL,
			((DWARFNumericAttribute) result).getValue());

		addCompUnit64();

		result = read(br, DW_AT_byte_size, DW_FORM_ref_addr);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		addCompUnit64();
		result = read(br, DW_AT_byte_size, DW_FORM_ref_addr);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be fffffffffffffffe", 0xff_ff_ff_ff_ff_ff_ff_feL,
			((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testIndirect() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			DW_FORM_data1.getId(),
			55,
			DW_FORM_ref4.getId(),
			0x00, 0x00, 0x00, 0xaa
			);
		// @formatter:on

		DWARFAttributeValue result = read(br, DW_AT_byte_size, DW_FORM_indirect);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = read(br, DW_AT_byte_size, DW_FORM_indirect);
		assertEquals("should be aa + cuOffset", 0xaa + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());
	}

}
