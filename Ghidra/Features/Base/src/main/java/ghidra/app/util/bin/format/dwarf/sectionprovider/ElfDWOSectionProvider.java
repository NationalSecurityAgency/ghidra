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
package ghidra.app.util.bin.format.dwarf.sectionprovider;

import java.io.File;
import java.io.IOException;
import java.nio.file.AccessMode;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.InflaterInputStream;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.elf.*;
import ghidra.util.task.TaskMonitor;

/**
 * Reads split DWARF sections from an ELF .dwo file. Sections omitted from the .dwo file,
 * notably .debug_addr, are supplied by the object containing its skeleton unit.
 */
public class ElfDWOSectionProvider implements DWARFSectionProvider {
	private final FileByteProvider fileProvider;
	private final ElfHeader elf;
	private final DWARFSectionProvider skeletonProvider;
	private final Map<String, ByteProvider> decompressedSections = new HashMap<>();

	public ElfDWOSectionProvider(File dwoFile, DWARFSectionProvider skeletonProvider)
			throws IOException {
		this.fileProvider = new FileByteProvider(dwoFile, null, AccessMode.READ);
		try {
			this.elf = new ElfHeader(fileProvider, null);
			elf.parse();
		}
		catch (IOException | ElfException e) {
			fileProvider.close();
			throw new IOException("Invalid split DWARF file: " + dwoFile, e);
		}
		this.skeletonProvider = skeletonProvider;
	}

	@Override
	public boolean hasSection(String... sectionNames) {
		for (String sectionName : sectionNames) {
			if (getDwoSection(sectionName) == null &&
				(!canUseSkeletonSection(sectionName) || !skeletonProvider.hasSection(sectionName))) {
				return false;
			}
		}
		return true;
	}

	@Override
	public ByteProvider getSectionAsByteProvider(String sectionName, TaskMonitor monitor)
			throws IOException {
		ElfSectionHeader section = getDwoSection(sectionName);
		if (section == null) {
			return canUseSkeletonSection(sectionName)
					? skeletonProvider.getSectionAsByteProvider(sectionName, monitor)
					: null;
		}
		if (!section.isCompressed()) {
			return new ByteProviderWrapper(fileProvider, section.getOffset(), section.getSize());
		}
		ByteProvider cached = decompressedSections.get(sectionName);
		if (cached != null) {
			return cached;
		}
		if (section.getLogicalSize() > Integer.MAX_VALUE) {
			throw new IOException("Split DWARF section is too large: " + sectionName);
		}
		BinaryReader reader = new BinaryReader(
			new ByteProviderWrapper(fileProvider, section.getOffset(), section.getSize()),
			elf.isLittleEndian());
		ElfCompressedSectionHeader header = ElfCompressedSectionHeader.read(reader, elf);
		if (header.getCh_type() != ElfCompressedSectionHeader.ELFCOMPRESS_ZLIB) {
			throw new IOException("Unsupported compression in split DWARF section: " + sectionName);
		}
		byte[] bytes;
		try (InflaterInputStream input = new InflaterInputStream(
			fileProvider.getInputStream(section.getOffset() + header.getHeaderSize()))) {
			bytes = input.readNBytes((int) section.getLogicalSize());
		}
		if (bytes.length != section.getLogicalSize()) {
			throw new IOException("Truncated split DWARF section: " + sectionName);
		}
		ByteProvider result = new ByteArrayProvider(bytes);
		decompressedSections.put(sectionName, result);
		return result;
	}

	private boolean canUseSkeletonSection(String sectionName) {
		return sectionName.equals(DWARFSectionId.DEBUG_ADDR.getSectionName()) ||
			sectionName.equals(DWARFSectionId.DEBUG_LINE.getSectionName()) ||
			sectionName.equals(DWARFSectionId.DEBUG_LINE_STR.getSectionName());
	}

	private ElfSectionHeader getDwoSection(String sectionName) {
		return elf.getSection("." + sectionName + ".dwo");
	}

	@Override
	public void close() {
		decompressedSections.clear();
		try {
			fileProvider.close();
		}
		catch (IOException e) {
			// Nothing to do while closing a read-only provider.
		}
	}
}
