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
package ghidra.app.util.bin.format.elf;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/**
 * Header at the beginning of an ELF compressed section.
 * <p>
 * See https://docs.oracle.com/cd/E53394_01/html/E54813/section_compression.html
 * <p>
 * <pre>
 * typedef struct {
 *      Elf32_Word      ch_type;
 *      Elf32_Word      ch_size;
 *      Elf32_Word      ch_addralign;
 * } Elf32_Chdr;
 * 
 * typedef struct {
 *      Elf64_Word      ch_type;
 *      Elf64_Word      ch_reserved;
 *      Elf64_Xword     ch_size;
 *      Elf64_Xword     ch_addralign;
 * } Elf64_Chdr;
 * </pre>
 */
public class ElfCompressedSectionHeader {
	public static final int ELFCOMPRESS_ZLIB = 1;
	//public static final int ELFCOMPRESS_LOOS = 0x60000000;
	//public static final int ELFCOMPRESS_HIOS = 0x6fffffff;
	//public static final int ELFCOMPRESS_LOPROC = 0x70000000;
	//public static final int ELFCOMPRESS_HIPROC = 0x7fffffff;
	private static final int SIZEOF_HEADER_32 = 12; // sizeof(word)*3 fields;
	private static final int SIZEOF_HEADER_64 = 24; // sizeof(word)*2 fields + sizeof(xword)*2 fields

	/**
	 * Reads an Elf(32|64)_Chdr from the current position in the supplied stream.
	 * 
	 * @param reader stream to read from
	 * @param elf ElfHeader that defines the format of the binary
	 * @return new {@link ElfCompressedSectionHeader} instance, never null
	 * @throws IOException if error reading the header
	 */
	public static ElfCompressedSectionHeader read(BinaryReader reader, ElfHeader elf)
			throws IOException {
		return elf.is32Bit() ? read32(reader) : read64(reader);
	}

	private int ch_type;	// compression algo
	private long ch_size;	// size, in bytes, of uncompressed data
	private long ch_addralign;	// alignment of the uncompressed data, sh_addralign
	private int headerSize;	// metadata about this header, used to skip the header when re-reading

	private ElfCompressedSectionHeader(int type, long size, long align, int headerSize) {
		this.ch_type = type;
		this.ch_size = size;
		this.ch_addralign = align;
		this.headerSize = headerSize;
	}

	/**
	 * {@return the compression type, see ELFCOMPRESS_ZLIB}
	 */
	public int getCh_type() {
		return ch_type;
	}

	/**
	 * {@return the uncompressed size}
	 */
	public long getCh_size() {
		return ch_size;
	}

	/**
	 * {@return the address alignment value}.
	 * <p>
	 * See {@link ElfSectionHeader#getAddressAlignment()}
	 */
	public long getCh_addralign() {
		return ch_addralign;
	}

	/**
	 * {@return the size of this header struct}
	 */
	public int getHeaderSize() {
		return headerSize;
	}

	//---------------------------------------------------------------------------------------------

	private static ElfCompressedSectionHeader read32(BinaryReader reader) throws IOException {
		int type = reader.readNextInt();
		long size = reader.readNextUnsignedInt();
		long align = reader.readNextUnsignedInt();

		return new ElfCompressedSectionHeader(type, size, align, SIZEOF_HEADER_32);
	}

	private static ElfCompressedSectionHeader read64(BinaryReader reader) throws IOException {
		int type = reader.readNextInt();
		/*long unused_reserved = */ reader.readNextUnsignedInt();
		long size = reader.readNextLong();
		long align = reader.readNextLong();

		return new ElfCompressedSectionHeader(type, size, align, SIZEOF_HEADER_64);
	}
}
