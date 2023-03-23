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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import static org.junit.Assert.*;

import java.io.StringWriter;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.bin.format.pdb2.pdbreader.C13FileChecksums.FileChecksum;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for PDB C13Section data.
 */
public class C13SectionsTest extends AbstractGenericTest {

	private static byte[] c13SectionsBytes;

	@Before
	public void setUp() throws Exception {
		c13SectionsBytes = createManyC13SectionsBytes();
	}

	//==============================================================================================
	@Test
	public void testC13Types() throws Exception {
		int ignore = 0x80000000;

		assertFalse(C13Type.ignore(0xf1));
		assertEquals(C13Type.SYMBOLS, C13Type.fromValue(0xf1));
		assertTrue(C13Type.ignore(0xf1 | ignore));
		assertEquals(C13Type.SYMBOLS, C13Type.fromValue(0xf1 | ignore));
		assertEquals(C13Type.SYMBOLS, C13Type.fromClassValue(C13Symbols.class));

		assertFalse(C13Type.ignore(0xf2));
		assertEquals(C13Type.LINES, C13Type.fromValue(0xf2));
		assertTrue(C13Type.ignore(0xf2 | ignore));
		assertEquals(C13Type.LINES, C13Type.fromValue(0xf2 | ignore));
		assertEquals(C13Type.LINES, C13Type.fromClassValue(C13Lines.class));

		assertFalse(C13Type.ignore(0xf3));
		assertEquals(C13Type.STRING_TABLE, C13Type.fromValue(0xf3));
		assertTrue(C13Type.ignore(0xf3 | ignore));
		assertEquals(C13Type.STRING_TABLE, C13Type.fromValue(0xf3 | ignore));
		assertEquals(C13Type.STRING_TABLE, C13Type.fromClassValue(C13StringTable.class));

		assertFalse(C13Type.ignore(0xf4));
		assertEquals(C13Type.FILE_CHECKSUMS, C13Type.fromValue(0xf4));
		assertTrue(C13Type.ignore(0xf4 | ignore));
		assertEquals(C13Type.FILE_CHECKSUMS, C13Type.fromValue(0xf4 | ignore));
		assertEquals(C13Type.FILE_CHECKSUMS, C13Type.fromClassValue(C13FileChecksums.class));

		assertFalse(C13Type.ignore(0xf5));
		assertEquals(C13Type.FRAMEDATA, C13Type.fromValue(0xf5));
		assertTrue(C13Type.ignore(0xf5 | ignore));
		assertEquals(C13Type.FRAMEDATA, C13Type.fromValue(0xf5 | ignore));
		assertEquals(C13Type.FRAMEDATA, C13Type.fromClassValue(C13FrameData.class));

		assertFalse(C13Type.ignore(0xf6));
		assertEquals(C13Type.INLINEE_LINES, C13Type.fromValue(0xf6));
		assertTrue(C13Type.ignore(0xf6 | ignore));
		assertEquals(C13Type.INLINEE_LINES, C13Type.fromValue(0xf6 | ignore));
		assertEquals(C13Type.INLINEE_LINES, C13Type.fromClassValue(C13InlineeLines.class));

		assertFalse(C13Type.ignore(0xf7));
		assertEquals(C13Type.CROSS_SCOPE_IMPORTS, C13Type.fromValue(0xf7));
		assertTrue(C13Type.ignore(0xf7 | ignore));
		assertEquals(C13Type.CROSS_SCOPE_IMPORTS, C13Type.fromValue(0xf7 | ignore));
		assertEquals(C13Type.CROSS_SCOPE_IMPORTS,
			C13Type.fromClassValue(C13CrossScopeImports.class));

		assertFalse(C13Type.ignore(0xf8));
		assertEquals(C13Type.CROSS_SCOPE_EXPORTS, C13Type.fromValue(0xf8));
		assertTrue(C13Type.ignore(0xf8 | ignore));
		assertEquals(C13Type.CROSS_SCOPE_EXPORTS, C13Type.fromValue(0xf8 | ignore));
		assertEquals(C13Type.CROSS_SCOPE_EXPORTS,
			C13Type.fromClassValue(C13CrossScopeExports.class));

		assertFalse(C13Type.ignore(0xf9));
		assertEquals(C13Type.IL_LINES, C13Type.fromValue(0xf9));
		assertTrue(C13Type.ignore(0xf9 | ignore));
		assertEquals(C13Type.IL_LINES, C13Type.fromValue(0xf9 | ignore));
		assertEquals(C13Type.IL_LINES, C13Type.fromClassValue(C13IlLines.class));

		assertFalse(C13Type.ignore(0xfa));
		assertEquals(C13Type.FUNC_MDTOKEN_MAP, C13Type.fromValue(0xfa));
		assertTrue(C13Type.ignore(0xfa | ignore));
		assertEquals(C13Type.FUNC_MDTOKEN_MAP, C13Type.fromValue(0xfa | ignore));
		assertEquals(C13Type.FUNC_MDTOKEN_MAP, C13Type.fromClassValue(C13FuncMdTokenMap.class));

		assertFalse(C13Type.ignore(0xfb));
		assertEquals(C13Type.TYPE_MDTOKEN_MAP, C13Type.fromValue(0xfb));
		assertTrue(C13Type.ignore(0xfb | ignore));
		assertEquals(C13Type.TYPE_MDTOKEN_MAP, C13Type.fromValue(0xfb | ignore));
		assertEquals(C13Type.TYPE_MDTOKEN_MAP, C13Type.fromClassValue(C13TypeMdTokenMap.class));

		assertFalse(C13Type.ignore(0xfc));
		assertEquals(C13Type.MERGED_ASSEMBLY_INPUT, C13Type.fromValue(0xfc));
		assertTrue(C13Type.ignore(0xfc | ignore));
		assertEquals(C13Type.MERGED_ASSEMBLY_INPUT, C13Type.fromValue(0xfc | ignore));
		assertEquals(C13Type.MERGED_ASSEMBLY_INPUT,
			C13Type.fromClassValue(C13MergedAssemblyInput.class));

		assertFalse(C13Type.ignore(0xfd));
		assertEquals(C13Type.COFF_SYMBOL_RVA, C13Type.fromValue(0xfd));
		assertTrue(C13Type.ignore(0xfd | ignore));
		assertEquals(C13Type.COFF_SYMBOL_RVA, C13Type.fromValue(0xfd | ignore));
		assertEquals(C13Type.COFF_SYMBOL_RVA, C13Type.fromClassValue(C13CoffSymbolRva.class));

		//---------------------------

		assertFalse(C13Type.ignore(0xff));
		assertEquals(C13Type.UNKNOWN, C13Type.fromValue(0xff));
		assertTrue(C13Type.ignore(0xff | ignore));
		assertEquals(C13Type.UNKNOWN, C13Type.fromValue(0xff | ignore));

		assertEquals(C13Type.ALL, C13Type.fromClassValue(C13Section.class));

	}

	//==============================================================================================
	@Test
	public void testC13NoneFileChecksum() throws Exception {
		byte[] bytes = createC13NoneFileChecksumBytes(0x1000);
		PdbByteReader reader = new PdbByteReader(bytes);
		FileChecksum fileChecksum = new FileChecksum(reader);
		String result = fileChecksum.toString();
		assertEquals("0x00001000, 0x00 NoneChecksumType(00): ", result);
	}

	@Test
	public void testC13Md5FileChecksum() throws Exception {
		byte[] bytes = createC13Md5FileChecksumBytes(0x1010);
		PdbByteReader reader = new PdbByteReader(bytes);
		FileChecksum fileChecksum = new FileChecksum(reader);
		String result = fileChecksum.toString();
		assertEquals("0x00001010, 0x10 Md5ChecksumType(01): " + "554433221100ffeeddccbbaa99887766",
			result);
	}

	@Test
	public void testC13Sha1FileChecksum() throws Exception {
		byte[] bytes = createC13Sha1FileChecksumBytes(0x1020);
		PdbByteReader reader = new PdbByteReader(bytes);
		FileChecksum fileChecksum = new FileChecksum(reader);
		String result = fileChecksum.toString();
		assertEquals(
			"0x00001020, 0x28 Sha1ChecksumType(02): " +
				"101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
			result);
	}

	@Test
	public void testC13Sha256FileChecksum() throws Exception {
		byte[] bytes = createC13Sha256FileChecksumBytes(0x1030);
		PdbByteReader reader = new PdbByteReader(bytes);
		FileChecksum fileChecksum = new FileChecksum(reader);
		String result = fileChecksum.toString();
		assertEquals("0x00001030, 0x40 Sha256ChecksumType(03): " +
			"00225566002255660022556600225566002255660022556600225566002255660022556600225566" +
			"002255660022556600225566002255660022556600225566",
			result);
	}

	@Test
	public void testC13UnknownFileChecksum() throws Exception {
		byte[] bytes =
			createC13FileChecksumBytes(0x1040, 0x04, new byte[] { 0x33, 0x44, 0x55, 0x66 });
		PdbByteReader reader = new PdbByteReader(bytes);
		FileChecksum fileChecksum = new FileChecksum(reader);
		String result = fileChecksum.toString();
		assertEquals("0x00001040, 0x04 UnknownChecksumType(04): 33445566", result);
	}

	@Test
	public void testC13NoneFileChecksumSizeMismatch() throws Exception {
		try {
			createC13FileChecksumBytes(0x1050, 0x00, new byte[] { 0x01 });
			fail("Expected an IllegalArgumentException");
		}
		catch (IllegalArgumentException e) {
			// Expected
		}
	}

	@Test
	public void testC13FileChecksums() throws Exception {
		PdbByteReader reader = new PdbByteReader(createC13FileChecksumsSectionBytes(0));
		C13Section section = C13Section.parse(reader, TaskMonitor.DUMMY);
		assertTrue(section instanceof C13FileChecksums);
		StringWriter writer = new StringWriter();
		section.dump(writer);
		assertEquals("C13FileChecksums--------------------------------------------\n" +
			"0x00002000, 0x00 NoneChecksumType(00): \n" +
			"0x00002010, 0x00 NoneChecksumType(00): \n" +
			"0x00002020, 0x10 Md5ChecksumType(01): 554433221100ffeeddccbbaa99887766\n" +
			"0x00002030, 0x10 Md5ChecksumType(01): 554433221100ffeeddccbbaa99887766\n" +
			"0x00002040, 0x28 Sha1ChecksumType(02): 101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f3031323334353637\n" +
			"0x00002050, 0x28 Sha1ChecksumType(02): 101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f3031323334353637\n" +
			"0x00002060, 0x40 Sha256ChecksumType(03): 00225566002255660022556600225566" +
			"002255660022556600225566002255660022556600225566002255660022556600225566" +
			"002255660022556600225566\n" +
			"0x00002070, 0x40 Sha256ChecksumType(03): 00225566002255660022556600225566" +
			"002255660022556600225566002255660022556600225566002255660022556600225566" +
			"002255660022556600225566\n" +
			"End C13FileChecksums----------------------------------------\n", writer.toString());
	}

	//==============================================================================================
	private byte[] createC13FileChecksumsSectionBytes(long twiddle) {
		PdbByteWriter recordsWriter = new PdbByteWriter();
		recordsWriter.putBytes(createC13NoneFileChecksumBytes(0x2000 + twiddle));
		recordsWriter.putBytes(createC13NoneFileChecksumBytes(0x2010 + twiddle));
		recordsWriter.putBytes(createC13Md5FileChecksumBytes(0x2020 + twiddle));
		recordsWriter.putBytes(createC13Md5FileChecksumBytes(0x2030 + twiddle));
		recordsWriter.putBytes(createC13Sha1FileChecksumBytes(0x2040 + twiddle));
		recordsWriter.putBytes(createC13Sha1FileChecksumBytes(0x2050 + twiddle));
		recordsWriter.putBytes(createC13Sha256FileChecksumBytes(0x2060 + twiddle));
		recordsWriter.putBytes(createC13Sha256FileChecksumBytes(0x2070 + twiddle));
		return createC13SectionBytes(C13Type.FILE_CHECKSUMS, recordsWriter.get());
	}

	/**
	 * Creates byte array of data for a C13 NoneFileChecksum
	 * @param offsetFilename unsigned integer value passed in a long
	 * @return final byte array of checksum data
	 */
	private byte[] createC13NoneFileChecksumBytes(long offsetFilename) {
		return createC13FileChecksumBytes(offsetFilename, 0x00, new byte[] {});
	}

	/**
	 * Creates byte array of data for a C13 Md5FileChecksum
	 * @param offsetFilename unsigned integer value passed in a long
	 * @return final byte array of checksum data
	 */
	private byte[] createC13Md5FileChecksumBytes(long offsetFilename) {
		return createC13FileChecksumBytes(offsetFilename, 0x01, new byte[] { 0x55, 0x44, 0x33, 0x22,
			0x11, 0x00, (byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb,
			(byte) 0xaa, (byte) 0x99, (byte) 0x88, 0x77, 0x66 });
	}

	/**
	 * Creates byte array of data for a C13 Sha1FileChecksum
	 * @param offsetFilename unsigned integer value passed in a long
	 * @return final byte array of checksum data
	 */
	private byte[] createC13Sha1FileChecksumBytes(long offsetFilename) {
		return createC13FileChecksumBytes(offsetFilename, 0x02,
			new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
				0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
				0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
				0x37 });
	}

	/**
	 * Creates byte array of data for a C13 Sha256FileChecksum
	 * @param offsetFilename unsigned integer value passed in a long
	 * @return final byte array of checksum data
	 */
	private byte[] createC13Sha256FileChecksumBytes(long offsetFilename) {
		return createC13FileChecksumBytes(offsetFilename, 0x03,
			new byte[] { 0x00, 0x22, 0x55, 0x66, 0x00, 0x22, 0x55, 0x66, 0x00, 0x22, 0x55, 0x66,
				0x00, 0x22, 0x55, 0x66, 0x00, 0x22, 0x55, 0x66, 0x00, 0x22, 0x55, 0x66, 0x00, 0x22,
				0x55, 0x66, 0x00, 0x22, 0x55, 0x66, 0x00, 0x22, 0x55, 0x66, 0x00, 0x22, 0x55, 0x66,
				0x00, 0x22, 0x55, 0x66, 0x00, 0x22, 0x55, 0x66, 0x00, 0x22, 0x55, 0x66, 0x00, 0x22,
				0x55, 0x66, 0x00, 0x22, 0x55, 0x66, 0x00, 0x22, 0x55, 0x66 });
	}

	/**
	 * Creates byte array of data for a C13FileChecksum
	 * @param offsetFilename unsigned integer value passed in a long
	 * @param type unsigned byte value passed in an integer
	 * @param bytes bytes of the checksum
	 * @return final byte array of checksum data
	 */
	private byte[] createC13FileChecksumBytes(long offsetFilename, int type, byte[] bytes) {
		int len = bytes.length;
		int neededLen;
		switch (type) {
			case 0x00: // None
				neededLen = 0;
				break;
			case 0x01: // MD5
				neededLen = 16;
				break;
			case 0x02: // SHA1
				neededLen = 40;
				break;
			case 0x03: // SHA256
				neededLen = 64;
				break;
			default: // Unknown type
				neededLen = len; // We really don't know what length is needed, but this passes test
				break;
		}
		if (len != neededLen || len > 0xff) {
			throw new IllegalArgumentException("bad length");
		}

		PdbByteWriter writer = new PdbByteWriter();
		//Consider ByteBuffer.allocate().put().put().put().put().array() model in future?
		writer.putUnsignedInt(offsetFilename);
		writer.putUnsignedByte(neededLen);
		writer.putUnsignedByte(type);
		writer.putBytes(bytes);
		writer.putAlign(0);
		return writer.get();

	}

	//==============================================================================================
	@Test
	public void testC13Lines() throws Exception {
		byte[] C13LinesSectionBytes = createC13LinesSectionBytes(0);
		PdbByteReader reader = new PdbByteReader(C13LinesSectionBytes);
		C13Section section = C13Section.parse(reader, TaskMonitor.DUMMY);
		assertTrue(section instanceof C13Lines);
		StringWriter writer = new StringWriter();
		section.dump(writer);
		assertEquals("C13Lines----------------------------------------------------\n" +
			"offCon: 0x00004000 segCon: 1 flags: 0x00000000 lenCon: 0x00000010\n" +
			"fileId: 001000, nLines: 3, lenFileBlock: 36\n" +
			"16 0x00004100 Statement\n" +
			"17 0x00004101 Statement\n" +
			"18 0x00004102 Statement\n" +
			"fileId: 002000, nLines: 2, lenFileBlock: 28\n" +
			"32 0x00004200 Expression\n" +
			"33 0x00004201 Expression\n" +
			"End C13Lines------------------------------------------------\n", writer.toString());
	}

	@Test
	public void testC13LinesWithColumns() throws Exception {
		byte[] C13LinesSectionBytes = createC13LinesWithColumnsSectionBytes(0);
		PdbByteReader reader = new PdbByteReader(C13LinesSectionBytes);
		C13Section section = C13Section.parse(reader, TaskMonitor.DUMMY);
		assertTrue(section instanceof C13Lines);
		StringWriter writer = new StringWriter();
		section.dump(writer);
		assertEquals("C13Lines----------------------------------------------------\n" +
			"offCon: 0x00004000 segCon: 1 flags: 0x00000001 lenCon: 0x00000010\n" +
			"fileId: 001000, nLines: 3, lenFileBlock: 48\n" +
			"   16:    0-   16-    1 0x00004100 Statement\n" +
			"   17:    2-   17-    3 0x00004101 Statement\n" +
			"   18:    4-   18-    5 0x00004102 Statement\n" +
			"fileId: 002000, nLines: 2, lenFileBlock: 36\n" +
			"   32:    0-   32-    1 0x00004200 Expression\n" +
			"   33:    2-   34-    3 0x00004201 Expression\n" +
			"End C13Lines------------------------------------------------\n", writer.toString());
	}

	@Test
	public void testC13IlLines() throws Exception {
		byte[] C13LinesSectionBytes = createC13IlLinesSectionBytes(0);
		PdbByteReader reader = new PdbByteReader(C13LinesSectionBytes);
		C13Section section = C13Section.parse(reader, TaskMonitor.DUMMY);
		assertTrue(section instanceof C13IlLines);
		StringWriter writer = new StringWriter();
		section.dump(writer);
		assertEquals("C13IlLines--------------------------------------------------\n" +
			"offCon: 0x00004000 segCon: 1 flags: 0x00000000 lenCon: 0x00000010\n" +
			"fileId: 001000, nLines: 3, lenFileBlock: 36\n" +
			"16 0x00004100 Statement\n" +
			"17 0x00004101 Statement\n" +
			"18 0x00004102 Statement\n" +
			"fileId: 002000, nLines: 2, lenFileBlock: 28\n" +
			"32 0x00004200 Expression\n" +
			"33 0x00004201 Expression\n" +
			"End C13IlLines----------------------------------------------\n", writer.toString());
	}

	@Test
	public void testC13IlLinesWithColumns() throws Exception {
		byte[] C13LinesSectionBytes = createC13IlLinesWithColumnsSectionBytes(0);
		PdbByteReader reader = new PdbByteReader(C13LinesSectionBytes);
		C13Section section = C13Section.parse(reader, TaskMonitor.DUMMY);
		assertTrue(section instanceof C13IlLines);
		StringWriter writer = new StringWriter();
		section.dump(writer);
		assertEquals("C13IlLines--------------------------------------------------\n" +
			"offCon: 0x00004000 segCon: 1 flags: 0x00000001 lenCon: 0x00000010\n" +
			"fileId: 001000, nLines: 3, lenFileBlock: 48\n" +
			"   16:    0-   16-    1 0x00004100 Statement\n" +
			"   17:    2-   17-    3 0x00004101 Statement\n" +
			"   18:    4-   18-    5 0x00004102 Statement\n" +
			"fileId: 002000, nLines: 2, lenFileBlock: 36\n" +
			"   32:    0-   32-    1 0x00004200 Expression\n" +
			"   33:    2-   34-    3 0x00004201 Expression\n" +
			"End C13IlLines----------------------------------------------\n", writer.toString());
	}

	//==============================================================================================
	// These are not the best mechanisms for putting together test data.  Possible future where
	// all PDB objects and read (parse) and write (serialize) methods to read/write byte streams.
	// Then we could compose nested objects as objects instead of byte arrays.
	private byte[] createC13LinesSectionBytes(long twiddle) {
		PdbByteWriter c13LinesWriter = new PdbByteWriter();
		createC13AbstractLinesSectionBytes(c13LinesWriter, twiddle);
		return createC13SectionBytes(C13Type.LINES, c13LinesWriter.get());
	}

	private byte[] createC13LinesWithColumnsSectionBytes(long twiddle) {
		PdbByteWriter c13LinesWriter = new PdbByteWriter();
		createC13AbstractLinesWithColumnsSectionBytes(c13LinesWriter, twiddle);
		return createC13SectionBytes(C13Type.LINES, c13LinesWriter.get());
	}

	private byte[] createC13IlLinesSectionBytes(long twiddle) {
		PdbByteWriter c13LinesWriter = new PdbByteWriter();
		createC13AbstractLinesSectionBytes(c13LinesWriter, twiddle);
		return createC13SectionBytes(C13Type.IL_LINES, c13LinesWriter.get());
	}

	private byte[] createC13IlLinesWithColumnsSectionBytes(long twiddle) {
		PdbByteWriter c13LinesWriter = new PdbByteWriter();
		createC13AbstractLinesWithColumnsSectionBytes(c13LinesWriter, twiddle);
		return createC13SectionBytes(C13Type.IL_LINES, c13LinesWriter.get());
	}

	private void createC13AbstractLinesSectionBytes(PdbByteWriter c13LinesWriter, long twiddle) {
		PdbByteWriter linesWriter1 = new PdbByteWriter();
		linesWriter1.putBytes(
			createC13LinesLineRecord(0x100L + twiddle, createBitVals(0x10, 0x00, true)));
		linesWriter1.putBytes(
			createC13LinesLineRecord(0x101L + twiddle, createBitVals(0x11, 0x00, true)));
		linesWriter1.putBytes(
			createC13LinesLineRecord(0x102L + twiddle, createBitVals(0x12, 0x00, true)));
		long nLines1 = 3L;
		byte[] lineRecordsBytes1 = linesWriter1.get();

		long fileId1 = 0x1000L;
		byte[] fileRecordBytes1 = createC13LinesFileRecord(fileId1, nLines1, lineRecordsBytes1);

		//---

		PdbByteWriter linesWriter2 = new PdbByteWriter();
		linesWriter2.putBytes(createC13LinesLineRecord(0x200L, createBitVals(0x20, 0x00, false)));
		linesWriter2.putBytes(createC13LinesLineRecord(0x201L, createBitVals(0x21, 0x01, false)));
		long nLines2 = 2L;
		byte[] lineRecordsBytes2 = linesWriter2.get();

		long fileId2 = 0x2000L;
		byte[] fileRecordBytes2 = createC13LinesFileRecord(fileId2, nLines2, lineRecordsBytes2);

		//---

		long offCon = 0x4000L; // unsigned int
		int segCon = 0x01; // unsigned short
		int flags = 0x0000; // unsigned short
		long lenCon = 0x10; // unsigned int

		// Writer to c13LinesWriter passed in as argument
		c13LinesWriter.putUnsignedInt(offCon);
		c13LinesWriter.putUnsignedShort(segCon);
		c13LinesWriter.putUnsignedShort(flags);
		c13LinesWriter.putUnsignedInt(lenCon);
		c13LinesWriter.putBytes(fileRecordBytes1);
		c13LinesWriter.putBytes(fileRecordBytes2);
	}

	private void createC13AbstractLinesWithColumnsSectionBytes(PdbByteWriter c13LinesWriter,
			long twiddle) {
		PdbByteWriter linesWriter1 = new PdbByteWriter();
		linesWriter1.putBytes(
			createC13LinesLineRecord(0x100L + twiddle, createBitVals(0x10, 0x00, true)));
		linesWriter1.putBytes(
			createC13LinesLineRecord(0x101L + twiddle, createBitVals(0x11, 0x00, true)));
		linesWriter1.putBytes(
			createC13LinesLineRecord(0x102L + twiddle, createBitVals(0x12, 0x00, true)));
		linesWriter1.putBytes(createC13LinesColumnRecord(0x0, 0x01));
		linesWriter1.putBytes(createC13LinesColumnRecord(0x2, 0x03));
		linesWriter1.putBytes(createC13LinesColumnRecord(0x4, 0x05));
		long nLines1 = 3L;
		byte[] lineRecordsBytes1 = linesWriter1.get();

		long fileId1 = 0x1000L;
		byte[] fileRecordBytes1 = createC13LinesFileRecord(fileId1, nLines1, lineRecordsBytes1);

		//---

		PdbByteWriter linesWriter2 = new PdbByteWriter();
		linesWriter2.putBytes(createC13LinesLineRecord(0x200L, createBitVals(0x20, 0x00, false)));
		linesWriter2.putBytes(createC13LinesLineRecord(0x201L, createBitVals(0x21, 0x01, false)));
		linesWriter2.putBytes(createC13LinesColumnRecord(0x0, 0x01));
		linesWriter2.putBytes(createC13LinesColumnRecord(0x2, 0x03));
		long nLines2 = 2L;
		byte[] lineRecordsBytes2 = linesWriter2.get();

		long fileId2 = 0x2000L;
		byte[] fileRecordBytes2 = createC13LinesFileRecord(fileId2, nLines2, lineRecordsBytes2);

		//---

		long offCon = 0x4000L; // unsigned int
		int segCon = 0x01; // unsigned short
		int flags = 0x0001; // unsigned short  .... 0x0001 bit means has columns
		long lenCon = 0x10; // unsigned int

		// Writer to c13LinesWriter passed in as argument
		c13LinesWriter.putUnsignedInt(offCon);
		c13LinesWriter.putUnsignedShort(segCon);
		c13LinesWriter.putUnsignedShort(flags);
		c13LinesWriter.putUnsignedInt(lenCon);
		c13LinesWriter.putBytes(fileRecordBytes1);
		c13LinesWriter.putBytes(fileRecordBytes2);
	}

	private byte[] createC13LinesFileRecord(long fileId, long nLines, byte[] lineRecordBytes) {
		long lenFileBlock = lineRecordBytes.length + 12;
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedInt(fileId);
		writer.putUnsignedInt(nLines);
		writer.putUnsignedInt(lenFileBlock);
		writer.putBytes(lineRecordBytes);
		return writer.get();
	}

	private byte[] createC13LinesLineRecord(long offset, long bitVals) {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedInt(offset);
		writer.putUnsignedInt(bitVals);
		return writer.get();
	}

	private byte[] createC13LinesColumnRecord(int offsetColumnStart,
			int offsetColumnEnd) {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedShort(offsetColumnStart);
		writer.putUnsignedShort(offsetColumnEnd);
		return writer.get();
	}

	private long createBitVals(long lineNumStart, long deltaLineEnd, boolean isStatement) {
		long bitVals = 0;
		if (lineNumStart > 0xffffffL) {
			fail("lineNumStart too big");
		}
		bitVals = lineNumStart;
		if (deltaLineEnd > 0x7fL) {
			fail("deltaLineEnd too big");
		}
		bitVals |= (deltaLineEnd << 24);
		bitVals |= (isStatement ? 0x80000000L : 0x0);
		return bitVals;
	}

	//==============================================================================================
	@Test
	public void testC13CrossScopeExports() throws Exception {
		byte[] C13CrossScopeExportsBytes = createC13CrossExportSectionBytes(0);
		PdbByteReader reader = new PdbByteReader(C13CrossScopeExportsBytes);
		C13Section section = C13Section.parse(reader, TaskMonitor.DUMMY);
		assertTrue(section instanceof C13CrossScopeExports);
		StringWriter writer = new StringWriter();
		section.dump(writer);
		assertEquals("C13CrossScopeExports----------------------------------------\n" +
			"0x00000100, 0x00001000\n" +
			"0x00000101, 0x00001001\n" +
			"End C13CrossScopeExports------------------------------------\n", writer.toString());
	}

	//==============================================================================================
	private byte[] createC13CrossExportSectionBytes(long twiddle) {
		PdbByteWriter recordsWriter = new PdbByteWriter();
		recordsWriter.putBytes(createC13CrossExportRecord(0x100L + twiddle, 0x1000L));
		recordsWriter.putBytes(createC13CrossExportRecord(0x101L + twiddle, 0x1001L));
		return createC13SectionBytes(C13Type.CROSS_SCOPE_EXPORTS, recordsWriter.get());
	}

	private byte[] createC13CrossExportRecord(long localId, long globalId) {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedInt(localId);
		writer.putUnsignedInt(globalId);
		return writer.get();
	}

	//==============================================================================================
	@Test
	public void testC13CrossScopeImports() throws Exception {
		byte[] C13CrossScopeImportsBytes = createC13CrossImportSectionBytes(0);
		PdbByteReader reader = new PdbByteReader(C13CrossScopeImportsBytes);
		C13Section section = C13Section.parse(reader, TaskMonitor.DUMMY);
		assertTrue(section instanceof C13CrossScopeImports);
		StringWriter writer = new StringWriter();
		section.dump(writer);
		assertEquals("C13CrossScopeImports----------------------------------------\n" +
			"0x00000100,     1 0x00001000\n" +
			"0x00000101,     2 0x00002000 0x00002001\n" +
			"End C13CrossScopeImports------------------------------------\n", writer.toString());
	}

	//==============================================================================================
	private byte[] createC13CrossImportSectionBytes(int twiddle) {
		PdbByteWriter recordsWriter = new PdbByteWriter();
		recordsWriter.putBytes(createC13CrossImportRecord(0x100 + twiddle, new long[] { 0x1000L }));
		recordsWriter.putBytes(
			createC13CrossImportRecord(0x101 + twiddle, new long[] { 0x2000L, 0x2001L }));
		return createC13SectionBytes(C13Type.CROSS_SCOPE_IMPORTS, recordsWriter.get());
	}

	private byte[] createC13CrossImportRecord(int offsetObjectFilePath, long[] referenceIds) {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putInt(offsetObjectFilePath);
		writer.putUnsignedInt(referenceIds.length);
		for (long id : referenceIds) {
			writer.putUnsignedInt(id);
		}
		return writer.get();
	}

	//==============================================================================================
	@Test
	public void testC13InlineeLines() throws Exception {
		byte[] C13InlineeBytes = createC13InlineeLinesSectionBytes(0);
		PdbByteReader reader = new PdbByteReader(C13InlineeBytes);
		C13Section section = C13Section.parse(reader, TaskMonitor.DUMMY);
		assertTrue(section instanceof C13InlineeLines);
		StringWriter writer = new StringWriter();
		section.dump(writer);
		assertEquals("C13InlineeLines---------------------------------------------\n" +
			"Signature: 0x000\n" +
			"0x000001000, 0x000001, 256\n" +
			"0x000002000, 0x000002, 512\n" +
			"End C13InlineeLines-----------------------------------------\n", writer.toString());
	}

	@Test
	public void testC13ExtendedInlineeLines() throws Exception {
		byte[] C13InlineeBytes = createC13ExtednedInlineeLinesSectionBytes();
		PdbByteReader reader = new PdbByteReader(C13InlineeBytes);
		C13Section section = C13Section.parse(reader, TaskMonitor.DUMMY);
		assertTrue(section instanceof C13InlineeLines);
		StringWriter writer = new StringWriter();
		section.dump(writer);
		assertEquals("C13InlineeLines---------------------------------------------\n" +
			"Signature: 0x001\n" +
			"0x000001000, 0x000001, 256\n" +
			"0x000002000, 0x000002, 512 0x000003 0x000004\n" +
			"End C13InlineeLines-----------------------------------------\n", writer.toString());
	}

	//==============================================================================================
	private byte[] createC13InlineeLinesSectionBytes(long twiddle) {
		PdbByteWriter recordsWriter = new PdbByteWriter();
		recordsWriter.putInt(0x00); // InlineeLines signature
		recordsWriter.putBytes(createC13InlineeLinesRecord(0x1000L + twiddle, 0x1, 0x100));
		recordsWriter.putBytes(createC13InlineeLinesRecord(0x2000L + twiddle, 0x2, 0x200));
		byte[] C13InlineeBytes =
			createC13SectionBytes(C13Type.INLINEE_LINES, recordsWriter.get());
		return C13InlineeBytes;
	}

	private byte[] createC13ExtednedInlineeLinesSectionBytes() {
		PdbByteWriter recordsWriter = new PdbByteWriter();
		recordsWriter.putInt(0x01); // ExtendedInlineeLines signature
		recordsWriter
				.putBytes(createC13ExtendedInlineeLinesRecord(0x1000L, 0x1, 0x100, new int[] {}));
		recordsWriter.putBytes(
			createC13ExtendedInlineeLinesRecord(0x2000L, 0x2, 0x200, new int[] { 0x3, 0x4 }));
		byte[] C13InlineeBytes =
			createC13SectionBytes(C13Type.INLINEE_LINES, recordsWriter.get());
		return C13InlineeBytes;
	}

	private byte[] createC13InlineeLinesRecord(long inlinee, int fileId, int sourceLineNum) {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedInt(inlinee);
		writer.putInt(fileId);
		writer.putInt(sourceLineNum);
		return writer.get();
	}

	private byte[] createC13ExtendedInlineeLinesRecord(long inlinee, int fileId, int sourceLineNum,
			int[] extraIds) {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putUnsignedInt(inlinee);
		writer.putInt(fileId);
		writer.putInt(sourceLineNum);
		writer.putUnsignedInt(extraIds.length);
		for (int id : extraIds) {
			writer.putInt(id);
		}
		return writer.get();
	}

	//==============================================================================================
	@Test
	public void testC13StringTableSectionIterator() throws Exception {
		PdbByteReader reader = new PdbByteReader(c13SectionsBytes);
		StringWriter writer = new StringWriter();
		C13SectionIterator<C13StringTable> iterator =
			new C13SectionIterator<>(reader, C13StringTable.class, true,
				TaskMonitor.DUMMY);
		while (iterator.hasNext()) {
			C13Section c13Section = iterator.next();
			c13Section.dump(writer);
		}
		assertEquals("C13StringTable----------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 1\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 1\n" +
			"000000 00\n" +
			"End C13StringTable------------------------------------------\n" +
			"C13StringTable----------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 2\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 2\n" +
			"000000 11 11\n" +
			"End C13StringTable------------------------------------------\n" +
			"C13StringTable----------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 1\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 1\n" +
			"000000 22\n" +
			"End C13StringTable------------------------------------------\n" +
			"C13StringTable----------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 2\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 2\n" +
			"000000 33 33\n" +
			"End C13StringTable------------------------------------------\n", writer.toString());
	}

	@Test
	public void testC13FileChecksumsSectionIterator() throws Exception {
		PdbByteReader reader = new PdbByteReader(c13SectionsBytes);
		StringWriter writer = new StringWriter();
		C13SectionIterator<C13FileChecksums> iterator =
			new C13SectionIterator<>(reader, C13FileChecksums.class, true,
				TaskMonitor.DUMMY);
		while (iterator.hasNext()) {
			C13Section c13Section = iterator.next();
			c13Section.dump(writer);
		}
		assertEquals("C13FileChecksums--------------------------------------------\n" +
			"0x00002000, 0x00 NoneChecksumType(00): \n" +
			"0x00002010, 0x00 NoneChecksumType(00): \n" +
			"0x00002020, 0x10 Md5ChecksumType(01): 554433221100ffeeddccbbaa99887766\n" +
			"0x00002030, 0x10 Md5ChecksumType(01): 554433221100ffeeddccbbaa99887766\n" +
			"0x00002040, 0x28 Sha1ChecksumType(02): 101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f3031323334353637\n" +
			"0x00002050, 0x28 Sha1ChecksumType(02): 101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f3031323334353637\n" +
			"0x00002060, 0x40 Sha256ChecksumType(03): 00225566002255660022556600225566" +
			"002255660022556600225566002255660022556600225566002255660022556600225566" +
			"002255660022556600225566\n" +
			"0x00002070, 0x40 Sha256ChecksumType(03): 00225566002255660022556600225566" +
			"002255660022556600225566002255660022556600225566002255660022556600225566" +
			"002255660022556600225566\n" +
			"End C13FileChecksums----------------------------------------\n" +
			"C13FileChecksums--------------------------------------------\n" +
			"0x00002001, 0x00 NoneChecksumType(00): \n" +
			"0x00002011, 0x00 NoneChecksumType(00): \n" +
			"0x00002021, 0x10 Md5ChecksumType(01): 554433221100ffeeddccbbaa99887766\n" +
			"0x00002031, 0x10 Md5ChecksumType(01): 554433221100ffeeddccbbaa99887766\n" +
			"0x00002041, 0x28 Sha1ChecksumType(02): 101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f3031323334353637\n" +
			"0x00002051, 0x28 Sha1ChecksumType(02): 101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f3031323334353637\n" +
			"0x00002061, 0x40 Sha256ChecksumType(03): 00225566002255660022556600225566" +
			"002255660022556600225566002255660022556600225566002255660022556600225566" +
			"002255660022556600225566\n" +
			"0x00002071, 0x40 Sha256ChecksumType(03): 00225566002255660022556600225566" +
			"002255660022556600225566002255660022556600225566002255660022556600225566" +
			"002255660022556600225566\n" +
			"End C13FileChecksums----------------------------------------\n" +
			"C13FileChecksums--------------------------------------------\n" +
			"0x00002002, 0x00 NoneChecksumType(00): \n" +
			"0x00002012, 0x00 NoneChecksumType(00): \n" +
			"0x00002022, 0x10 Md5ChecksumType(01): 554433221100ffeeddccbbaa99887766\n" +
			"0x00002032, 0x10 Md5ChecksumType(01): 554433221100ffeeddccbbaa99887766\n" +
			"0x00002042, 0x28 Sha1ChecksumType(02): 101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f3031323334353637\n" +
			"0x00002052, 0x28 Sha1ChecksumType(02): 101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f3031323334353637\n" +
			"0x00002062, 0x40 Sha256ChecksumType(03): 00225566002255660022556600225566" +
			"002255660022556600225566002255660022556600225566002255660022556600225566" +
			"002255660022556600225566\n" +
			"0x00002072, 0x40 Sha256ChecksumType(03): 00225566002255660022556600225566" +
			"002255660022556600225566002255660022556600225566002255660022556600225566" +
			"002255660022556600225566\n" +
			"End C13FileChecksums----------------------------------------\n" +
			"C13FileChecksums--------------------------------------------\n" +
			"0x00002003, 0x00 NoneChecksumType(00): \n" +
			"0x00002013, 0x00 NoneChecksumType(00): \n" +
			"0x00002023, 0x10 Md5ChecksumType(01): 554433221100ffeeddccbbaa99887766\n" +
			"0x00002033, 0x10 Md5ChecksumType(01): 554433221100ffeeddccbbaa99887766\n" +
			"0x00002043, 0x28 Sha1ChecksumType(02): 101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f3031323334353637\n" +
			"0x00002053, 0x28 Sha1ChecksumType(02): 101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f3031323334353637\n" +
			"0x00002063, 0x40 Sha256ChecksumType(03): 00225566002255660022556600225566" +
			"002255660022556600225566002255660022556600225566002255660022556600225566" +
			"002255660022556600225566\n" +
			"0x00002073, 0x40 Sha256ChecksumType(03): 00225566002255660022556600225566" +
			"002255660022556600225566002255660022556600225566002255660022556600225566" +
			"002255660022556600225566\n" +
			"End C13FileChecksums----------------------------------------\n", writer.toString());
	}

	@Test
	public void testC13FrameDataSectionIterator() throws Exception {
		PdbByteReader reader = new PdbByteReader(c13SectionsBytes);
		StringWriter writer = new StringWriter();
		C13SectionIterator<C13FrameData> iterator =
			new C13SectionIterator<>(reader, C13FrameData.class, true,
				TaskMonitor.DUMMY);
		while (iterator.hasNext()) {
			C13Section c13Section = iterator.next();
			c13Section.dump(writer);
		}
		assertEquals("C13FrameData------------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 1\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 1\n" +
			"000000 00\n" +
			"End C13FrameData--------------------------------------------\n" +
			"C13FrameData------------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 2\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 2\n" +
			"000000 11 11\n" +
			"End C13FrameData--------------------------------------------\n" +
			"C13FrameData------------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 1\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 1\n" +
			"000000 22\n" +
			"End C13FrameData--------------------------------------------\n" +
			"C13FrameData------------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 2\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 2\n" +
			"000000 33 33\n" +
			"End C13FrameData--------------------------------------------\n", writer.toString());
	}

	@Test
	public void testC13InlineeLinesSectionIterator() throws Exception {
		PdbByteReader reader = new PdbByteReader(c13SectionsBytes);
		StringWriter writer = new StringWriter();
		C13SectionIterator<C13InlineeLines> iterator =
			new C13SectionIterator<>(reader, C13InlineeLines.class, true,
				TaskMonitor.DUMMY);
		while (iterator.hasNext()) {
			C13Section c13Section = iterator.next();
			c13Section.dump(writer);
		}
		assertEquals("C13InlineeLines---------------------------------------------\n" +
			"Signature: 0x000\n" +
			"0x000001000, 0x000001, 256\n" +
			"0x000002000, 0x000002, 512\n" +
			"End C13InlineeLines-----------------------------------------\n" +
			"C13InlineeLines---------------------------------------------\n" +
			"Signature: 0x000\n" +
			"0x000001001, 0x000001, 256\n" +
			"0x000002001, 0x000002, 512\n" +
			"End C13InlineeLines-----------------------------------------\n" +
			"C13InlineeLines---------------------------------------------\n" +
			"Signature: 0x000\n" +
			"0x000001002, 0x000001, 256\n" +
			"0x000002002, 0x000002, 512\n" +
			"End C13InlineeLines-----------------------------------------\n" +
			"C13InlineeLines---------------------------------------------\n" +
			"Signature: 0x000\n" +
			"0x000001003, 0x000001, 256\n" +
			"0x000002003, 0x000002, 512\n" +
			"End C13InlineeLines-----------------------------------------\n", writer.toString());
	}

	@Test
	public void testC13CrossScopeImportsSectionIterator() throws Exception {
		PdbByteReader reader = new PdbByteReader(c13SectionsBytes);
		StringWriter writer = new StringWriter();
		C13SectionIterator<C13CrossScopeImports> iterator =
			new C13SectionIterator<>(reader, C13CrossScopeImports.class, true,
				TaskMonitor.DUMMY);
		while (iterator.hasNext()) {
			C13Section c13Section = iterator.next();
			c13Section.dump(writer);
		}
		assertEquals("C13CrossScopeImports----------------------------------------\n" +
			"0x00000100,     1 0x00001000\n" +
			"0x00000101,     2 0x00002000 0x00002001\n" +
			"End C13CrossScopeImports------------------------------------\n" +
			"C13CrossScopeImports----------------------------------------\n" +
			"0x00000101,     1 0x00001000\n" +
			"0x00000102,     2 0x00002000 0x00002001\n" +
			"End C13CrossScopeImports------------------------------------\n" +
			"C13CrossScopeImports----------------------------------------\n" +
			"0x00000102,     1 0x00001000\n" +
			"0x00000103,     2 0x00002000 0x00002001\n" +
			"End C13CrossScopeImports------------------------------------\n" +
			"C13CrossScopeImports----------------------------------------\n" +
			"0x00000103,     1 0x00001000\n" +
			"0x00000104,     2 0x00002000 0x00002001\n" +
			"End C13CrossScopeImports------------------------------------\n", writer.toString());
	}

	@Test
	public void testC13CrossScopeExportsSectionIterator() throws Exception {
		PdbByteReader reader = new PdbByteReader(c13SectionsBytes);
		StringWriter writer = new StringWriter();
		C13SectionIterator<C13CrossScopeExports> iterator =
			new C13SectionIterator<>(reader, C13CrossScopeExports.class, true,
				TaskMonitor.DUMMY);
		while (iterator.hasNext()) {
			C13Section c13Section = iterator.next();
			c13Section.dump(writer);
		}
		assertEquals("C13CrossScopeExports----------------------------------------\n" +
			"0x00000100, 0x00001000\n" +
			"0x00000101, 0x00001001\n" +
			"End C13CrossScopeExports------------------------------------\n" +
			"C13CrossScopeExports----------------------------------------\n" +
			"0x00000101, 0x00001000\n" +
			"0x00000102, 0x00001001\n" +
			"End C13CrossScopeExports------------------------------------\n" +
			"C13CrossScopeExports----------------------------------------\n" +
			"0x00000102, 0x00001000\n" +
			"0x00000103, 0x00001001\n" +
			"End C13CrossScopeExports------------------------------------\n" +
			"C13CrossScopeExports----------------------------------------\n" +
			"0x00000103, 0x00001000\n" +
			"0x00000104, 0x00001001\n" +
			"End C13CrossScopeExports------------------------------------\n", writer.toString());
	}

	@Test
	public void testC13IlLinesSectionIterator() throws Exception {
		PdbByteReader reader = new PdbByteReader(c13SectionsBytes);
		StringWriter writer = new StringWriter();
		C13SectionIterator<C13IlLines> iterator =
			new C13SectionIterator<>(reader, C13IlLines.class, true,
				TaskMonitor.DUMMY);
		while (iterator.hasNext()) {
			C13Section c13Section = iterator.next();
			c13Section.dump(writer);
		}
		assertEquals("C13IlLines--------------------------------------------------\n" +
			"offCon: 0x00004000 segCon: 1 flags: 0x00000000 lenCon: 0x00000010\n" +
			"fileId: 001000, nLines: 3, lenFileBlock: 36\n" +
			"16 0x00004100 Statement\n" +
			"17 0x00004101 Statement\n" +
			"18 0x00004102 Statement\n" +
			"fileId: 002000, nLines: 2, lenFileBlock: 28\n" +
			"32 0x00004200 Expression\n" +
			"33 0x00004201 Expression\n" +
			"End C13IlLines----------------------------------------------\n" +
			"C13IlLines--------------------------------------------------\n" +
			"offCon: 0x00004000 segCon: 1 flags: 0x00000000 lenCon: 0x00000010\n" +
			"fileId: 001000, nLines: 3, lenFileBlock: 36\n" +
			"16 0x00004101 Statement\n" +
			"17 0x00004102 Statement\n" +
			"18 0x00004103 Statement\n" +
			"fileId: 002000, nLines: 2, lenFileBlock: 28\n" +
			"32 0x00004200 Expression\n" +
			"33 0x00004201 Expression\n" +
			"End C13IlLines----------------------------------------------\n" +
			"C13IlLines--------------------------------------------------\n" +
			"offCon: 0x00004000 segCon: 1 flags: 0x00000000 lenCon: 0x00000010\n" +
			"fileId: 001000, nLines: 3, lenFileBlock: 36\n" +
			"16 0x00004102 Statement\n" +
			"17 0x00004103 Statement\n" +
			"18 0x00004104 Statement\n" +
			"fileId: 002000, nLines: 2, lenFileBlock: 28\n" +
			"32 0x00004200 Expression\n" +
			"33 0x00004201 Expression\n" +
			"End C13IlLines----------------------------------------------\n" +
			"C13IlLines--------------------------------------------------\n" +
			"offCon: 0x00004000 segCon: 1 flags: 0x00000000 lenCon: 0x00000010\n" +
			"fileId: 001000, nLines: 3, lenFileBlock: 36\n" +
			"16 0x00004103 Statement\n" +
			"17 0x00004104 Statement\n" +
			"18 0x00004105 Statement\n" +
			"fileId: 002000, nLines: 2, lenFileBlock: 28\n" +
			"32 0x00004200 Expression\n" +
			"33 0x00004201 Expression\n" +
			"End C13IlLines----------------------------------------------\n", writer.toString());
	}

	@Test
	public void testC13FuncMdTokenMapSectionIterator() throws Exception {
		PdbByteReader reader = new PdbByteReader(c13SectionsBytes);
		StringWriter writer = new StringWriter();
		C13SectionIterator<C13FuncMdTokenMap> iterator =
			new C13SectionIterator<>(reader, C13FuncMdTokenMap.class, true,
				TaskMonitor.DUMMY);
		while (iterator.hasNext()) {
			C13Section c13Section = iterator.next();
			c13Section.dump(writer);
		}
		assertEquals("C13FuncMdTokenMap-------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 1\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 1\n" +
			"000000 00\n" +
			"End C13FuncMdTokenMap---------------------------------------\n" +
			"C13FuncMdTokenMap-------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 2\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 2\n" +
			"000000 11 11\n" +
			"End C13FuncMdTokenMap---------------------------------------\n" +
			"C13FuncMdTokenMap-------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 1\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 1\n" +
			"000000 22\n" +
			"End C13FuncMdTokenMap---------------------------------------\n" +
			"C13FuncMdTokenMap-------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 2\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 2\n" +
			"000000 33 33\n" +
			"End C13FuncMdTokenMap---------------------------------------\n", writer.toString());
	}

	@Test
	public void testC13TypeMdTokenMapSectionIterator() throws Exception {
		PdbByteReader reader = new PdbByteReader(c13SectionsBytes);
		StringWriter writer = new StringWriter();
		C13SectionIterator<C13TypeMdTokenMap> iterator =
			new C13SectionIterator<>(reader, C13TypeMdTokenMap.class, true,
				TaskMonitor.DUMMY);
		while (iterator.hasNext()) {
			C13Section c13Section = iterator.next();
			c13Section.dump(writer);
		}
		assertEquals("C13TypeMdTokenMap-------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 1\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 1\n" +
			"000000 00\n" +
			"End C13TypeMdTokenMap---------------------------------------\n" +
			"C13TypeMdTokenMap-------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 2\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 2\n" +
			"000000 11 11\n" +
			"End C13TypeMdTokenMap---------------------------------------\n" +
			"C13TypeMdTokenMap-------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 1\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 1\n" +
			"000000 22\n" +
			"End C13TypeMdTokenMap---------------------------------------\n" +
			"C13TypeMdTokenMap-------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 2\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 2\n" +
			"000000 33 33\n" +
			"End C13TypeMdTokenMap---------------------------------------\n", writer.toString());
	}

	@Test
	public void testC13MergedAssemblyInputSectionIterator() throws Exception {
		PdbByteReader reader = new PdbByteReader(c13SectionsBytes);
		StringWriter writer = new StringWriter();
		C13SectionIterator<C13MergedAssemblyInput> iterator =
			new C13SectionIterator<>(reader, C13MergedAssemblyInput.class, true,
				TaskMonitor.DUMMY);
		while (iterator.hasNext()) {
			C13Section c13Section = iterator.next();
			c13Section.dump(writer);
		}
		assertEquals("C13MergedAssemblyInput--------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 1\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 1\n" +
			"000000 00\n" +
			"End C13MergedAssemblyInput----------------------------------\n" +
			"C13MergedAssemblyInput--------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 2\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 2\n" +
			"000000 11 11\n" +
			"End C13MergedAssemblyInput----------------------------------\n" +
			"C13MergedAssemblyInput--------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 1\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 1\n" +
			"000000 22\n" +
			"End C13MergedAssemblyInput----------------------------------\n" +
			"C13MergedAssemblyInput--------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 2\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 2\n" +
			"000000 33 33\n" +
			"End C13MergedAssemblyInput----------------------------------\n", writer.toString());
	}

	@Test
	public void testC13CoffSymbolRvaSectionIterator() throws Exception {
		PdbByteReader reader = new PdbByteReader(c13SectionsBytes);
		StringWriter writer = new StringWriter();
		C13SectionIterator<C13CoffSymbolRva> iterator =
			new C13SectionIterator<>(reader, C13CoffSymbolRva.class, true,
				TaskMonitor.DUMMY);
		while (iterator.hasNext()) {
			C13Section c13Section = iterator.next();
			c13Section.dump(writer);
		}
		assertEquals("C13CoffSymbolRva--------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 1\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 1\n" +
			"000000 00\n" +
			"End C13CoffSymbolRva----------------------------------------\n" +
			"C13CoffSymbolRva--------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 2\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 2\n" +
			"000000 11 11\n" +
			"End C13CoffSymbolRva----------------------------------------\n" +
			"C13CoffSymbolRva--------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 1\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 1\n" +
			"000000 22\n" +
			"End C13CoffSymbolRva----------------------------------------\n" +
			"C13CoffSymbolRva--------------------------------------------\n" +
			"***NOT IMPLEMENTED***  Bytes follow...\n" +
			"limit: 2\n" +
			"index: 0\n" +
			"first: 0\n" +
			"last: 2\n" +
			"000000 33 33\n" +
			"End C13CoffSymbolRva----------------------------------------\n", writer.toString());
	}

	@Test
	// We care comparing enum types instead of comparing long dump strings because the string
	// would be quite large.
	public void testC13AllSectionIterator() throws Exception {
		PdbByteReader reader = new PdbByteReader(c13SectionsBytes);
		C13SectionIterator<C13Section> iterator =
			new C13SectionIterator<>(reader, C13Section.class, true, TaskMonitor.DUMMY);
		int expectedTypeVal = C13Type.SYMBOLS.getValue();
		int cnt = 0;
		while (iterator.hasNext()) {
			C13Section c13Section = iterator.next();
			C13Type found = C13Type.fromClassValue(c13Section.getClass());
			if (found.getValue() != expectedTypeVal) {
				fail("Section type not expected");
			}
			cnt++;
			if (cnt % 2 == 0) { // see createManyC13SectionBytes... doing pairs of two of same
				if (expectedTypeVal == C13Type.COFF_SYMBOL_RVA.getValue()) {
					expectedTypeVal = C13Type.SYMBOLS.getValue(); // another round
				}
				else {
					expectedTypeVal++;
				}
			}
		}
	}

	//==============================================================================================
	private byte[] createManyC13SectionsBytes() {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putBytes(createC13SectionBytes(C13Type.SYMBOLS, new byte[] { 0x00 }));
		writer.putBytes(createC13SectionBytes(C13Type.SYMBOLS, new byte[] { 0x11, 0x11 }));
		writer.putBytes(createC13LinesSectionBytes(0));
		writer.putBytes(createC13LinesSectionBytes(1));
		writer.putBytes(createC13SectionBytes(C13Type.STRING_TABLE, new byte[] { 0x00 }));
		writer.putBytes(createC13SectionBytes(C13Type.STRING_TABLE, new byte[] { 0x11, 0x11 }));
		writer.putBytes(createC13FileChecksumsSectionBytes(0));
		writer.putBytes(createC13FileChecksumsSectionBytes(1));
		writer.putBytes(createC13SectionBytes(C13Type.FRAMEDATA, new byte[] { 0x00 }));
		writer.putBytes(createC13SectionBytes(C13Type.FRAMEDATA, new byte[] { 0x11, 0x11 }));
		writer.putBytes(createC13InlineeLinesSectionBytes(0));
		writer.putBytes(createC13InlineeLinesSectionBytes(1));
		writer.putBytes(createC13CrossImportSectionBytes(0));
		writer.putBytes(createC13CrossImportSectionBytes(1));
		writer.putBytes(createC13CrossExportSectionBytes(0));
		writer.putBytes(createC13CrossExportSectionBytes(1));
		writer.putBytes(createC13IlLinesSectionBytes(0));
		writer.putBytes(createC13IlLinesSectionBytes(1));
		writer.putBytes(createC13SectionBytes(C13Type.FUNC_MDTOKEN_MAP, new byte[] { 0x00 }));
		writer.putBytes(createC13SectionBytes(C13Type.FUNC_MDTOKEN_MAP, new byte[] { 0x11, 0x11 }));
		writer.putBytes(createC13SectionBytes(C13Type.TYPE_MDTOKEN_MAP, new byte[] { 0x00 }));
		writer.putBytes(createC13SectionBytes(C13Type.TYPE_MDTOKEN_MAP, new byte[] { 0x11, 0x11 }));
		writer.putBytes(createC13SectionBytes(C13Type.MERGED_ASSEMBLY_INPUT, new byte[] { 0x00 }));
		writer.putBytes(
			createC13SectionBytes(C13Type.MERGED_ASSEMBLY_INPUT, new byte[] { 0x11, 0x11 }));
		writer.putBytes(createC13SectionBytes(C13Type.COFF_SYMBOL_RVA, new byte[] { 0x00 }));
		writer.putBytes(createC13SectionBytes(C13Type.COFF_SYMBOL_RVA, new byte[] { 0x11, 0x11 }));
		// another round
		writer.putBytes(createC13SectionBytes(C13Type.SYMBOLS, new byte[] { 0x22 }));
		writer.putBytes(createC13SectionBytes(C13Type.SYMBOLS, new byte[] { 0x33, 0x33 }));
		writer.putBytes(createC13LinesSectionBytes(2));
		writer.putBytes(createC13LinesSectionBytes(3));
		writer.putBytes(createC13SectionBytes(C13Type.STRING_TABLE, new byte[] { 0x22 }));
		writer.putBytes(createC13SectionBytes(C13Type.STRING_TABLE, new byte[] { 0x33, 0x33 }));
		writer.putBytes(createC13FileChecksumsSectionBytes(2));
		writer.putBytes(createC13FileChecksumsSectionBytes(3));
		writer.putBytes(createC13SectionBytes(C13Type.FRAMEDATA, new byte[] { 0x22 }));
		writer.putBytes(createC13SectionBytes(C13Type.FRAMEDATA, new byte[] { 0x33, 0x33 }));
		writer.putBytes(createC13InlineeLinesSectionBytes(2));
		writer.putBytes(createC13InlineeLinesSectionBytes(3));
		writer.putBytes(createC13CrossImportSectionBytes(2));
		writer.putBytes(createC13CrossImportSectionBytes(3));
		writer.putBytes(createC13CrossExportSectionBytes(2));
		writer.putBytes(createC13CrossExportSectionBytes(3));
		writer.putBytes(createC13IlLinesSectionBytes(2));
		writer.putBytes(createC13IlLinesSectionBytes(3));
		writer.putBytes(createC13SectionBytes(C13Type.FUNC_MDTOKEN_MAP, new byte[] { 0x22 }));
		writer.putBytes(createC13SectionBytes(C13Type.FUNC_MDTOKEN_MAP, new byte[] { 0x33, 0x33 }));
		writer.putBytes(createC13SectionBytes(C13Type.TYPE_MDTOKEN_MAP, new byte[] { 0x22 }));
		writer.putBytes(createC13SectionBytes(C13Type.TYPE_MDTOKEN_MAP, new byte[] { 0x33, 0x33 }));
		writer.putBytes(createC13SectionBytes(C13Type.MERGED_ASSEMBLY_INPUT, new byte[] { 0x22 }));
		writer.putBytes(
			createC13SectionBytes(C13Type.MERGED_ASSEMBLY_INPUT, new byte[] { 0x33, 0x33 }));
		writer.putBytes(createC13SectionBytes(C13Type.COFF_SYMBOL_RVA, new byte[] { 0x22 }));
		writer.putBytes(createC13SectionBytes(C13Type.COFF_SYMBOL_RVA, new byte[] { 0x33, 0x33 }));
		return writer.get();
	}

	//==============================================================================================
	/**
	 * Creates C13Section from record bytes; thus it creates a header with type and length, which
	 * is then followed by the record bytes
	 * @return byte array of full C13Section
	 */
	private byte[] createC13SectionBytes(C13Type type, byte[] recordBytes) {
		PdbByteWriter writer = new PdbByteWriter();
		writer.putInt(type.getValue());
		writer.putInt(recordBytes.length);
		writer.putBytes(recordBytes);
		return writer.get();
	}

}
