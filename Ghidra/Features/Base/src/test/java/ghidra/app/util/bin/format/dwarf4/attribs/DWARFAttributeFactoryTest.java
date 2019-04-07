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
package ghidra.app.util.bin.format.dwarf4.attribs;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.dwarf4.DWARFCompilationUnit;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFForm;
import ghidra.app.util.bin.format.dwarf4.next.*;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.NullSectionProvider;
import ghidra.program.model.listing.Program;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;

/**
 * Test reading binary representations of DWARF attributes from raw bytes.
 */
public class DWARFAttributeFactoryTest extends AbstractGenericTest {

	private DWARFProgram prog;
	private StringTable stringTable;
	private DWARFAttributeFactory attribFactory;
	private DWARFCompilationUnit cu;
	private DWARFCompilationUnit cu64;

	@Before
	public void setUp() throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder("Test", true);
		Program ghidraProgram = builder.getProgram();

		prog = new DWARFProgram(ghidraProgram, new DWARFImportOptions(), TaskMonitor.DUMMY,
			new NullSectionProvider());
		stringTable = prog.getDebugStrings();
		attribFactory = prog.getAttributeFactory();

		cu = new DWARFCompilationUnit(prog, 0x1000, 0x2000, 0, DWARFCompilationUnit.DWARF_32,
			(short) 4, 0, (byte) 8, 0, 0, null);
		cu64 = new DWARFCompilationUnit(prog, 0x2000, 0x4000, 0, DWARFCompilationUnit.DWARF_64,
			(short) 4, 0, (byte) 8, 0, 0, null);

		assertTrue("These tests were written for big endian", prog.isBigEndian());
	}

	private BinaryReader br(byte... bytes) {
		return new BinaryReader(new ByteArrayProvider(bytes), prog.isLittleEndian());
	}

	@Test
	public void testStr() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			/* str1 */ (byte) 'a', (byte) 'b', (byte) 0,
			/* str2 */ (byte) 'c', (byte) 0,
			/* str3 */ (byte) 'x', (byte) 'y', (byte) '\n', (byte) 0,
			/* guard byte for test */ (byte) 0xff);
		// @formatter:on
		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_string);
		assertTrue("Should be string", result instanceof DWARFStringAttribute);
		assertEquals("ab", ((DWARFStringAttribute) result).getValue(null));

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_string);
		assertTrue("Should be string", result instanceof DWARFStringAttribute);
		assertEquals("c", ((DWARFStringAttribute) result).getValue(null));

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_string);
		assertTrue("Should be string", result instanceof DWARFStringAttribute);
		assertEquals("Test reading nullterm string with non-printable chars", "xy\n",
			((DWARFStringAttribute) result).getValue(null));

		assertEquals("guard byte", (byte) 0xff, br.readNextByte());
	}

	@Test
	public void testStrp_32() throws IOException {
		prog.getDebugStrings().add(1, "string1 at 1");
		prog.getDebugStrings().add(100, "string2 at 100");

		// @formatter:off
		BinaryReader br = br(
			/* ref to str2 */ (byte) 0, (byte) 0, (byte) 0, (byte) 100,
			/* ref to str1 */ (byte) 0, (byte) 0, (byte) 0, (byte) 1,
			/* ref to str2 ofcut */ (byte) 0, (byte) 0, (byte) 0, (byte) 101,
			/* guard byte for test */ (byte) 0xff);
		// @formatter:on

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_strp);
		assertTrue("Should be string", result instanceof DWARFStringAttribute);
		assertEquals("string2 at 100", ((DWARFStringAttribute) result).getValue(stringTable));

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_strp);
		assertTrue("Should be string", result instanceof DWARFStringAttribute);
		assertEquals("string1 at 1", ((DWARFStringAttribute) result).getValue(stringTable));

		// test string ref to substring of string2
		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_strp);
		assertTrue("Should be string", result instanceof DWARFStringAttribute);
		assertEquals("tring2 at 100", ((DWARFStringAttribute) result).getValue(stringTable));

		assertEquals("guard byte", (byte) 0xff, br.readNextByte());
	}

	@Test
	public void testStrp_64() throws IOException {
		prog.getDebugStrings().add(1, "string1 at 1");
		prog.getDebugStrings().add(100, "string2 at 100");

		// @formatter:off
		BinaryReader br = br(
			/* str1 */ (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 100,
			/* str2 */ (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 1,
			/* guard byte for test */ (byte) 0xff);
		// @formatter:on

		DWARFAttributeValue result1 = attribFactory.read(br, cu64, DWARFForm.DW_FORM_strp);
		assertTrue("Should be string", result1 instanceof DWARFStringAttribute);
		assertEquals("string2 at 100", ((DWARFStringAttribute) result1).getValue(stringTable));

		DWARFAttributeValue result2 = attribFactory.read(br, cu64, DWARFForm.DW_FORM_strp);
		assertTrue("Should be string", result2 instanceof DWARFStringAttribute);
		assertEquals("string1 at 1", ((DWARFStringAttribute) result2).getValue(stringTable));

		assertEquals("guard byte", (byte) 0xff, br.readNextByte());
	}

	@Test
	public void testData1() throws IOException {
		BinaryReader br = br((byte) 55, (byte) 0xfe);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_data1);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_data1);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be -2", -2, ((DWARFNumericAttribute) result).getValue());
		assertEquals("should be fe", 0xfe, ((DWARFNumericAttribute) result).getUnsignedValue());
	}

	@Test
	public void testData2() throws IOException {
		BinaryReader br = br((byte) 0, (byte) 55, (byte) 0xff, (byte) 0xfe);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_data2);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_data2);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be -2", -2, ((DWARFNumericAttribute) result).getValue());
		assertEquals("should be fffe", 0xfffe, ((DWARFNumericAttribute) result).getUnsignedValue());
	}

	@Test
	public void testData4() throws IOException {
		BinaryReader br = br((byte) 0, (byte) 0, (byte) 0, (byte) 55, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xfe);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_data4);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_data4);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be -2", -2, ((DWARFNumericAttribute) result).getValue());
		assertEquals("should be 0xfffffffe", 0xffff_fffeL,
			((DWARFNumericAttribute) result).getUnsignedValue());
	}

	@Test
	public void testData8() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 55,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe);
		// @formatter:on

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_data8);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_data8);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		// these next two asserts are probably the same test as there isn't a way to
		// simulate unsigned long values
		assertEquals("should be -2", -2, ((DWARFNumericAttribute) result).getValue());
		assertEquals("should be 0xfffffffffffffffe", 0xffff_ffff_ffff_fffeL,
			((DWARFNumericAttribute) result).getUnsignedValue());
	}

	@Test
	public void testSData() throws IOException {
		BinaryReader br = br((byte) 0, (byte) 55, (byte) 0xff, (byte) 0x7e);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_sdata);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 0", 0, ((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_sdata);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_sdata);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be -129", -129, ((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testUData() throws IOException {
		BinaryReader br = br((byte) 0, (byte) 55, (byte) 0xff, (byte) 0x7e);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_udata);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 0", 0, ((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_udata);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_udata);
		assertTrue("Should be const", result instanceof DWARFNumericAttribute);
		assertEquals("should be 16255", 16255, ((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testAddr() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 55,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe);
		// @formatter:on

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_addr);
		assertTrue("Should be addr", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getUnsignedValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_addr);
		assertTrue("Should be addr", result instanceof DWARFNumericAttribute);
		assertEquals("should be feffffffffffffff", 0xfffffffffffffffeL,
			((DWARFNumericAttribute) result).getUnsignedValue());
	}

	@Test
	public void testBlock1() throws IOException {
		BinaryReader br = br((byte) 1, (byte) 0x55, (byte) 0);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_block1);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 1", 1, ((DWARFBlobAttribute) result).getLength());
		assertEquals("should be 0x55", 0x55, ((DWARFBlobAttribute) result).getBytes()[0]);

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_block1);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 0", 0, ((DWARFBlobAttribute) result).getLength());

		byte[] bytes = new byte[1 + 255 /* max_ubyte */];
		bytes[0] = (byte) 0xff;
		result = attribFactory.read(br(bytes), cu, DWARFForm.DW_FORM_block1);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 255", 255, ((DWARFBlobAttribute) result).getLength());
	}

	@Test
	public void testBlock2() throws IOException {
		BinaryReader br = br((byte) 0, (byte) 1, (byte) 0x55, (byte) 0, (byte) 0);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_block2);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 1", 1, ((DWARFBlobAttribute) result).getLength());
		assertEquals("should be 0x55", 0x55, ((DWARFBlobAttribute) result).getBytes()[0]);

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_block1);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 0", 0, ((DWARFBlobAttribute) result).getLength());

		byte[] bytes = new byte[2 + 0xffff /* max_ushort */];
		bytes[0] = (byte) 0xff;
		bytes[1] = (byte) 0xff;
		result = attribFactory.read(br(bytes), cu, DWARFForm.DW_FORM_block2);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 64k", 0xffff, ((DWARFBlobAttribute) result).getLength());
	}

	@Test
	public void testBlock4() throws IOException {
		BinaryReader br = br((byte) 0, (byte) 0, (byte) 0, (byte) 1, (byte) 0x55, (byte) 0,
			(byte) 0, (byte) 0, (byte) 0);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_block4);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 1", 1, ((DWARFBlobAttribute) result).getLength());
		assertEquals("should be 0x55", 0x55, ((DWARFBlobAttribute) result).getBytes()[0]);

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_block4);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 0", 0, ((DWARFBlobAttribute) result).getLength());

		// Test max block4 sized chunk
		byte[] bytes = new byte[4 + DWARFAttributeFactory.MAX_BLOCK4_SIZE];
		//DWARFAttributeFactory.MAX_BLOCK4_SIZE == 0x00_10_00_00
		bytes[0] = (byte) 0x00;
		bytes[1] = (byte) 0x10;
		bytes[2] = (byte) 0x00;
		bytes[3] = (byte) 0x00;
		result = attribFactory.read(br(bytes), cu, DWARFForm.DW_FORM_block4);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be MAX_BLOCK4_SIZE", DWARFAttributeFactory.MAX_BLOCK4_SIZE,
			((DWARFBlobAttribute) result).getLength());

		// Test block4 size that is larger than max
		bytes = new byte[4 + DWARFAttributeFactory.MAX_BLOCK4_SIZE + 1];
		//DWARFAttributeFactory.MAX_BLOCK4_SIZE == 0x00_10_00_00 + 1 == 0x00_10_00_01
		bytes[0] = (byte) 0x00;
		bytes[1] = (byte) 0x10;
		bytes[2] = (byte) 0x00;
		bytes[3] = (byte) 0x01;
		try {
			result = attribFactory.read(br(bytes), cu, DWARFForm.DW_FORM_block4);
			fail(
				"Should not get here, dw_form_block4 size should have been larger than max sanity check");
		}
		catch (IOException ioe) {
			// good
		}
	}

	@Test
	public void testBlock() throws IOException {
		BinaryReader br = br((byte) 1, (byte) 0x55, (byte) 0);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_block);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 1", 1, ((DWARFBlobAttribute) result).getLength());
		assertEquals("should be 0x55", 0x55, ((DWARFBlobAttribute) result).getBytes()[0]);

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_block);
		assertTrue("Should be block", result instanceof DWARFBlobAttribute);
		assertEquals("should be 0", 0, ((DWARFBlobAttribute) result).getLength());
	}

	@Test
	public void testExprLoc() throws IOException {
		BinaryReader br = br((byte) 1, (byte) 0x55, (byte) 0);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_exprloc);
		assertTrue("Should be exprloc", result instanceof DWARFBlobAttribute);
		assertEquals("should be 1", 1, ((DWARFBlobAttribute) result).getLength());
		assertEquals("should be 0x55", 0x55, ((DWARFBlobAttribute) result).getBytes()[0]);

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_exprloc);
		assertTrue("Should be exprloc", result instanceof DWARFBlobAttribute);
		assertEquals("should be 0", 0, ((DWARFBlobAttribute) result).getLength());
	}

	@Test
	public void testFlag() throws IOException {
		BinaryReader br = br((byte) 55, (byte) 0x00);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_flag);
		assertTrue("Should be flag", result instanceof DWARFBooleanAttribute);
		assertEquals("should be true", true, ((DWARFBooleanAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_flag);
		assertTrue("Should be flag", result instanceof DWARFBooleanAttribute);
		assertEquals("should be false", false, ((DWARFBooleanAttribute) result).getValue());
	}

	@Test
	public void testFlagPresent() throws IOException {
		BinaryReader br = br(new byte[] {} /* no bytes needed for flag_present */);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_flag_present);
		assertTrue("Should be flag", result instanceof DWARFBooleanAttribute);
		assertEquals("should be true", true, ((DWARFBooleanAttribute) result).getValue());
	}

	@Test
	public void testRef1() throws IOException {
		BinaryReader br = br((byte) 55, (byte) 0xfe);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_ref1);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55 + cuOffset", 55 + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_ref1);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be fe + cuOffset", 0xfe + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testRef2() throws IOException {
		BinaryReader br = br((byte) 0, (byte) 55, (byte) 0xff, (byte) 0xfe);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_ref2);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55 + cuOffset", 55 + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_ref2);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be fffe + cuOffset", 0xfffe + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testRef4() throws IOException {
		BinaryReader br = br((byte) 0, (byte) 0, (byte) 0, (byte) 55, (byte) 0xff, (byte) 0xff,
			(byte) 0xff, (byte) 0xfe);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_ref4);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55 + cuOffset", 55 + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_ref4);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be fffffffe + cuOffset", 0xff_ff_ff_feL + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testSecOffset() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			(byte) 0, (byte) 0, (byte) 0, (byte) 55,
			(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 56
		);
		// @formatter:on

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_sec_offset);
		assertTrue("Should be ptr", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu64, DWARFForm.DW_FORM_sec_offset);
		assertTrue("Should be ptr", result instanceof DWARFNumericAttribute);
		assertEquals("should be 56", 56, ((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testRef8() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 55,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe);
		// @formatter:on

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_ref8);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55 + cuOffset", 55 + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_ref8);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be fffffffffffffffe + cuOffset",
			0xff_ff_ff_ff_ff_ff_ff_feL + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testRefUData() throws IOException {
		BinaryReader br = br((byte) 55, (byte) 0xff, (byte) 0x7e);

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_ref_udata);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55 + cuOffset", 55 + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_ref_udata);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 0x3f7f + cuOffset", 0x3f7f + cu.getStartOffset(),
			((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testRefAddr() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			(byte) 0, (byte) 0, (byte) 0, (byte) 55,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
			(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 55,
			(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe
			);
		// @formatter:on

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_ref_addr);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_ref_addr);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be ffffffff", 0xff_ff_ff_ffL,
			((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu64, DWARFForm.DW_FORM_ref_addr);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be 55", 55, ((DWARFNumericAttribute) result).getValue());

		result = attribFactory.read(br, cu64, DWARFForm.DW_FORM_ref_addr);
		assertTrue("Should be ref", result instanceof DWARFNumericAttribute);
		assertEquals("should be fffffffffffffffe", 0xff_ff_ff_ff_ff_ff_ff_feL,
			((DWARFNumericAttribute) result).getValue());
	}

	@Test
	public void testIndirect() throws IOException {
		// @formatter:off
		BinaryReader br = br(
			(byte)DWARFForm.DW_FORM_data1.getValue(),
			(byte) 55,
			(byte)DWARFForm.DW_FORM_ref4.getValue(),
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xaa
			);
		// @formatter:on

		DWARFAttributeValue result = attribFactory.read(br, cu, DWARFForm.DW_FORM_indirect);
		DWARFIndirectAttribute dia = (DWARFIndirectAttribute) result;
		DWARFNumericAttribute nestedAttr = (DWARFNumericAttribute) dia.getValue();
		assertEquals("should be 55", 55, nestedAttr.getValue());

		result = attribFactory.read(br, cu, DWARFForm.DW_FORM_indirect);
		dia = (DWARFIndirectAttribute) result;
		nestedAttr = (DWARFNumericAttribute) dia.getValue();
		assertEquals("should be aa + cuOffset", 0xaa + cu.getStartOffset(), nestedAttr.getValue());
	}

}
