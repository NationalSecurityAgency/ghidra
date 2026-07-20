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
package ghidra.app.util.bin.format.pe;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;

public class ExportDataDirectoryTest {

	@Test
	public void testUnsignedNameOrdinalIndexes() throws Exception {
		assertNamedExportAtFunctionIndex(0x7fff);
		assertNamedExportAtFunctionIndex(0x8000);
		assertNamedExportAtFunctionIndex(0xffff);
	}

	@Test
	public void testLowIndexNamedAndOrdinalOnlyExports() throws Exception {
		ExportInfo[] exports = parseExports(createPeWithExport(1));

		assertEquals(2, exports.length);
		assertEquals(1, exports[0].getOrdinal());
		assertEquals("", exports[0].getName());
		assertFalse(exports[0].isForwarded());
		assertEquals(2, exports[1].getOrdinal());
		assertEquals("BugReproTarget", exports[1].getName());
		assertFalse(exports[1].isForwarded());
	}

	private void assertNamedExportAtFunctionIndex(int functionIndex) throws IOException {
		ExportInfo[] exports = parseExports(createPeWithExport(functionIndex));

		assertEquals(2, exports.length);
		assertEquals(1, exports[0].getOrdinal());
		assertEquals("", exports[0].getName());
		assertEquals(functionIndex + 1, exports[1].getOrdinal());
		assertEquals("BugReproTarget", exports[1].getName());
		assertEquals(0x10001010L, exports[1].getAddress());
		assertFalse(exports[1].isForwarded());
	}

	private ExportInfo[] parseExports(byte[] peBytes) throws IOException {
		try (ByteArrayProvider provider = new ByteArrayProvider(peBytes)) {
			PortableExecutable pe = new PortableExecutable(provider, SectionLayout.FILE);
			DataDirectory[] dataDirectories =
				pe.getNTHeader().getOptionalHeader().getDataDirectories();
			assertNotNull(dataDirectories);
			assertTrue(
				dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_EXPORT] instanceof ExportDataDirectory);
			return ((ExportDataDirectory) dataDirectories[OptionalHeader.IMAGE_DIRECTORY_ENTRY_EXPORT])
					.getExports();
		}
	}

	private byte[] createPeWithExport(int namedFunctionIndex) {
		int numberOfFunctions = namedFunctionIndex + 1;
		int textRva = 0x1000;
		int textRaw = 0x200;
		int textRawSize = 0x200;
		int exportRva = 0x2000;
		int exportRaw = 0x400;

		int functionsOffset = ExportDataDirectory.IMAGE_SIZEOF_EXPORT_DIRECTORY;
		int namesOffset = functionsOffset + numberOfFunctions * 4;
		int ordinalsOffset = namesOffset + 4;
		int dllNameOffset = ordinalsOffset + 2;
		int exportNameOffset = dllNameOffset + "test.dll".length() + 1;
		int exportSize = exportNameOffset + "BugReproTarget".length() + 1;
		int exportRawSize = align(exportSize, 0x200);
		int fileSize = exportRaw + exportRawSize;
		byte[] bytes = new byte[fileSize];

		putAscii(bytes, 0, "MZ");
		putInt(bytes, 0x3c, 0x80);
		putAscii(bytes, 0x80, "PE\0\0");
		putShort(bytes, 0x84, 0x14c);
		putShort(bytes, 0x86, 2);
		putShort(bytes, 0x94, 0xe0);
		putShort(bytes, 0x96, 0x210e);

		int optional = 0x98;
		putShort(bytes, optional, 0x10b);
		putInt(bytes, optional + 16, 0x1010);
		putInt(bytes, optional + 28, 0x10000000);
		putInt(bytes, optional + 32, 0x200);
		putInt(bytes, optional + 36, 0x200);
		putInt(bytes, optional + 56, align(exportRva + exportSize, 0x200));
		putInt(bytes, optional + 60, 0x200);
		putShort(bytes, optional + 68, 2);
		putInt(bytes, optional + 92, OptionalHeader.IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
		putInt(bytes, optional + 96, exportRva);
		putInt(bytes, optional + 100, exportSize);

		int section = optional + 0xe0;
		putAscii(bytes, section, ".text");
		putInt(bytes, section + 8, textRawSize);
		putInt(bytes, section + 12, textRva);
		putInt(bytes, section + 16, textRawSize);
		putInt(bytes, section + 20, textRaw);
		putInt(bytes, section + 36, 0x60000020);

		section += 0x28;
		putAscii(bytes, section, ".edata");
		putInt(bytes, section + 8, exportSize);
		putInt(bytes, section + 12, exportRva);
		putInt(bytes, section + 16, exportRawSize);
		putInt(bytes, section + 20, exportRaw);
		putInt(bytes, section + 36, 0x40000040);

		putInt(bytes, exportRaw + 12, exportRva + dllNameOffset);
		putInt(bytes, exportRaw + 16, 1);
		putInt(bytes, exportRaw + 20, numberOfFunctions);
		putInt(bytes, exportRaw + 24, 1);
		putInt(bytes, exportRaw + 28, exportRva + functionsOffset);
		putInt(bytes, exportRaw + 32, exportRva + namesOffset);
		putInt(bytes, exportRaw + 36, exportRva + ordinalsOffset);

		putInt(bytes, exportRaw + functionsOffset, textRva);
		putInt(bytes, exportRaw + functionsOffset + namedFunctionIndex * 4, textRva + 0x10);
		putInt(bytes, exportRaw + namesOffset, exportRva + exportNameOffset);
		putShort(bytes, exportRaw + ordinalsOffset, namedFunctionIndex);
		putAscii(bytes, exportRaw + dllNameOffset, "test.dll\0");
		putAscii(bytes, exportRaw + exportNameOffset, "BugReproTarget\0");
		return bytes;
	}

	private int align(int value, int alignment) {
		return (value + alignment - 1) & -alignment;
	}

	private void putShort(byte[] bytes, int offset, int value) {
		bytes[offset] = (byte) value;
		bytes[offset + 1] = (byte) (value >>> 8);
	}

	private void putInt(byte[] bytes, int offset, int value) {
		bytes[offset] = (byte) value;
		bytes[offset + 1] = (byte) (value >>> 8);
		bytes[offset + 2] = (byte) (value >>> 16);
		bytes[offset + 3] = (byte) (value >>> 24);
	}

	private void putAscii(byte[] bytes, int offset, String value) {
		byte[] ascii = value.getBytes(StandardCharsets.US_ASCII);
		System.arraycopy(ascii, 0, bytes, offset, ascii.length);
	}
}
