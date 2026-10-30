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
package ghidra.app.util.opinion;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.app.util.importer.ProgramLoader;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

/**
 * Tests {@link NeLoader}, in particular its handling of entry table "constant" bundles
 * (type {@code 0xfe}), which hold 16-bit values rather than addresses.
 */
public class NeLoaderTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final int NE_HEADER_OFFSET = 0x40;
	private static final int SEGMENT_TABLE_OFFSET = 0x80;
	private static final int RESIDENT_NAME_TABLE_OFFSET = 0x88;
	private static final int IMPORTED_NAME_TABLE_OFFSET = 0x99;
	private static final int MODULE_REF_TABLE_OFFSET = 0x9a;
	private static final int ENTRY_TABLE_OFFSET = 0x9a;
	private static final int ENTRY_TABLE_LENGTH = 19;
	private static final int NONRESIDENT_NAME_TABLE_OFFSET = 0xad;
	private static final int NONRESIDENT_NAME_TABLE_LENGTH = 24;
	private static final int SEGMENT_CONTENT_OFFSET = 0x100;
	private static final int SEGMENT_CONTENT_LENGTH = 0x20;
	private static final int FILE_LENGTH = SEGMENT_CONTENT_OFFSET + SEGMENT_CONTENT_LENGTH;

	/**
	 * Builds a minimal but valid NE image.  Its entry table intentionally has a constant bundle
	 * (ordinals 2 and 3) sandwiched between two segment bundles (ordinals 1 and 4) so that ordinal
	 * alignment across the constant bundle is exercised.
	 */
	private static byte[] buildNeImage() {
		byte[] image = new byte[FILE_LENGTH];

		// DOS header: "MZ" signature with e_lfanew pointing at the NE header
		image[0] = 'M';
		image[1] = 'Z';
		putInt(image, 0x3c, NE_HEADER_OFFSET);

		int ne = NE_HEADER_OFFSET;

		// Information Block (IMAGE_OS2_HEADER)
		putShort(image, ne + 0x00, 0x454e); // ne_magic "NE"
		putByte(image, ne + 0x02, 5); // ne_ver
		putByte(image, ne + 0x03, 1); // ne_rev
		putShort(image, ne + 0x04, ENTRY_TABLE_OFFSET - ne); // ne_enttab
		putShort(image, ne + 0x06, ENTRY_TABLE_LENGTH); // ne_cbenttab
		putByte(image, ne + 0x0c, 0x01); // ne_flags_prog: single data
		putByte(image, ne + 0x0d, 0x00); // ne_flags_app
		putShort(image, ne + 0x0e, 1); // ne_autodata
		putShort(image, ne + 0x1c, 1); // ne_cseg
		putShort(image, ne + 0x1e, 0); // ne_cmod
		putShort(image, ne + 0x20, NONRESIDENT_NAME_TABLE_LENGTH); // ne_cbnrestab
		putShort(image, ne + 0x22, SEGMENT_TABLE_OFFSET - ne); // ne_segtab
		// ne_rsrctab == ne_restab signals that there are no resources
		putShort(image, ne + 0x24, RESIDENT_NAME_TABLE_OFFSET - ne); // ne_rsrctab
		putShort(image, ne + 0x26, RESIDENT_NAME_TABLE_OFFSET - ne); // ne_restab
		putShort(image, ne + 0x28, MODULE_REF_TABLE_OFFSET - ne); // ne_modtab
		putShort(image, ne + 0x2a, IMPORTED_NAME_TABLE_OFFSET - ne); // ne_imptab
		putInt(image, ne + 0x2c, NONRESIDENT_NAME_TABLE_OFFSET); // ne_nrestab (absolute)
		putShort(image, ne + 0x32, 0); // ne_align: alignment shift of 0
		putByte(image, ne + 0x36, 2); // ne_exetyp: Windows

		// Segment Table: one code segment
		int st = SEGMENT_TABLE_OFFSET;
		putShort(image, st + 0x00, SEGMENT_CONTENT_OFFSET); // sector offset of segment data
		putShort(image, st + 0x02, SEGMENT_CONTENT_LENGTH); // length of segment in file
		putShort(image, st + 0x04, 0x0000); // flagword: code, not 32-bit, no relocations
		putShort(image, st + 0x06, SEGMENT_CONTENT_LENGTH); // minimum allocation size

		// Resident Name Table: ordinal 1 -> "START", ordinal 4 -> "AFTER"
		int rnt = RESIDENT_NAME_TABLE_OFFSET;
		rnt = putName(image, rnt, "START", 1);
		rnt = putName(image, rnt, "AFTER", 4);
		image[rnt++] = 0; // table terminator

		// Imported Name Table: empty
		image[IMPORTED_NAME_TABLE_OFFSET] = 0;

		// Entry Table: segment bundle (ordinal 1), constant bundle (ordinals 2 and 3),
		// segment bundle (ordinal 4)
		int et = ENTRY_TABLE_OFFSET;
		image[et++] = 0x01; // bundle count
		image[et++] = 0x01; // bundle type: segment 1
		image[et++] = 0x00; // flagword
		putShort(image, et, 0x0000); // offset
		et += 2;
		image[et++] = 0x02; // bundle count
		image[et++] = (byte) 0xfe; // bundle type: constant
		image[et++] = 0x00; // flagword
		putShort(image, et, 0x1000); // constant value of ordinal 2
		et += 2;
		image[et++] = 0x00; // flagword
		putShort(image, et, 0x000c); // constant value of ordinal 3
		et += 2;
		image[et++] = 0x01; // bundle count
		image[et++] = 0x01; // bundle type: segment 1
		image[et++] = 0x00; // flagword
		putShort(image, et, 0x0010); // offset
		et += 2;
		image[et++] = 0x00; // entry table terminator
		assertEquals(ENTRY_TABLE_LENGTH, et - ENTRY_TABLE_OFFSET);

		// Non-Resident Name Table: ordinal 2 -> "__AHINCR", ordinal 3 -> "__AHSHIFT"
		int nrnt = NONRESIDENT_NAME_TABLE_OFFSET;
		nrnt = putName(image, nrnt, "__AHINCR", 2);
		nrnt = putName(image, nrnt, "__AHSHIFT", 3);
		image[nrnt++] = 0; // table terminator
		assertEquals(NONRESIDENT_NAME_TABLE_LENGTH, nrnt - NONRESIDENT_NAME_TABLE_OFFSET);

		return image;
	}

	/**
	 * Writes a resident/non-resident name table entry (length, name, ordinal) and returns the
	 * offset just past it.
	 */
	private static int putName(byte[] image, int offset, String name, int ordinal) {
		image[offset++] = (byte) name.length();
		for (int i = 0; i < name.length(); i++) {
			image[offset++] = (byte) name.charAt(i);
		}
		putShort(image, offset, ordinal);
		return offset + 2;
	}

	private static void putByte(byte[] image, int offset, int value) {
		image[offset] = (byte) value;
	}

	private static void putShort(byte[] image, int offset, int value) {
		image[offset] = (byte) value;
		image[offset + 1] = (byte) (value >> 8);
	}

	private static void putInt(byte[] image, int offset, int value) {
		putShort(image, offset, value);
		putShort(image, offset + 2, value >> 16);
	}

	private SymbolTable loadAndGetSymbolTable(Program[] programHolder) throws Exception {
		LoadResults<Program> loadResults = ProgramLoader.builder()
				.source(buildNeImage())
				.name("minimal.exe")
				.language("x86:LE:16:Real Mode")
				.loaders(NeLoader.class)
				.load();
		Program program = loadResults.getPrimaryDomainObject(this);
		programHolder[0] = program;
		return program.getSymbolTable();
	}

	/**
	 * A constant entry table bundle must not produce an address, label, or external entry point.
	 */
	@Test
	public void testConstantBundleCreatesNoSymbol() throws Exception {
		Program[] holder = new Program[1];
		try {
			SymbolTable symbolTable = loadAndGetSymbolTable(holder);

			assertFalse("constant ordinal name should not become a symbol",
				symbolTable.getSymbols("__AHINCR").hasNext());
			assertFalse("constant ordinal name should not become a symbol",
				symbolTable.getSymbols("__AHSHIFT").hasNext());

			// the segment bundled entries that surround the constant bundle are still resolved,
			// which proves the ordinals stayed aligned across the constant bundle
			assertTrue("ordinal 1 should be labeled",
				symbolTable.getSymbols("START").hasNext());
			assertTrue("ordinal 4 should be labeled",
				symbolTable.getSymbols("AFTER").hasNext());
		}
		finally {
			holder[0].release(this);
		}
	}

	/**
	 * The value of a constant entry table bundle must be exposed as a single member enum under
	 * the {@code /NE/defines} category.
	 */
	@Test
	public void testConstantBundleCreatesEnum() throws Exception {
		Program[] holder = new Program[1];
		try {
			loadAndGetSymbolTable(holder);
			DataTypeManager dtm = holder[0].getDataTypeManager();
			CategoryPath path = new CategoryPath("/NE/defines");

			assertNotNull("expected a /NE/defines category", dtm.getCategory(path));

			DataType ahincrType = dtm.getDataType(path, "const___AHINCR");
			assertTrue("expected const___AHINCR to be an enum but got " + ahincrType,
				ahincrType instanceof Enum);
			Enum ahincr = (Enum) ahincrType;
			assertEquals(2, ahincr.getLength());
			assertEquals(1, ahincr.getCount());
			assertEquals(0x1000, ahincr.getValue("__AHINCR"));

			DataType ahshiftType = dtm.getDataType(path, "const___AHSHIFT");
			assertTrue("expected const___AHSHIFT to be an enum but got " + ahshiftType,
				ahshiftType instanceof Enum);
			Enum ahshift = (Enum) ahshiftType;
			assertEquals(2, ahshift.getLength());
			assertEquals(1, ahshift.getCount());
			assertEquals(0x000c, ahshift.getValue("__AHSHIFT"));
		}
		finally {
			holder[0].release(this);
		}
	}
}
