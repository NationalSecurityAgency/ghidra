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
package ghidra.app.util.bin.format.ubi;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.coff.CoffException;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveHeader;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveMemberHeader;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a fat_header structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/fat.h">mach-o/fat.h</a>
 * @see <a href="https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/machine.h">mach/machine.h</a> 
 */
public class FatHeader {
	public final static int FAT_MAGIC = 0xcafebabe;
	public final static int FAT_CIGAM = 0xbebafeca;

    private int magic;
	private int nfat_arch;
	private List<FatArch> architectures = new ArrayList<>();
	private List<MachHeader> machHeaders = new ArrayList<>();
	private List<Long> machStarts = new ArrayList<>();
	private List<Long> machSizes = new ArrayList<>();

	public FatHeader(ByteProvider provider)
            throws IOException, UbiException, MachException {
		BinaryReader reader = new BinaryReader(provider, false/*always big endian*/);

		magic = reader.readNextInt();

		if (magic != FAT_MAGIC && magic != FAT_CIGAM) {
			throw new UbiException("Invalid UBI file.");
		}

		nfat_arch = reader.readNextInt();
		if (nfat_arch > 0x1000 || nfat_arch < 0) {
			throw new UbiException("Invalid UBI file.");
		}

		for (int i = 0 ; i < nfat_arch ; ++i) {
			architectures.add(new FatArch(reader));
		}

		for (FatArch fatarch : architectures) {
			ByteProviderWrapper wrapper =
				new ByteProviderWrapper(provider, fatarch.getOffset(), fatarch.getSize());

			// It could be a Mach-O or a COFF archive
			CoffArchiveHeader caf = null;
			try {
				caf = CoffArchiveHeader.read(wrapper, TaskMonitor.DUMMY);
			}
			catch (CoffException e) {
				throw new UbiException(e);
			}
			if (caf != null) {
				for (CoffArchiveMemberHeader camh : caf.getArchiveMemberHeaders()) {
					wrapper = new ByteProviderWrapper(provider,
						fatarch.getOffset() + camh.getPayloadOffset(), camh.getSize());
					try {
						machHeaders.add(new MachHeader(wrapper));
						machStarts.add(fatarch.getOffset() + camh.getPayloadOffset());
						machSizes.add(camh.getSize());
					}
					catch (MachException e) {
						// Could be __.SYMDEF archive member instead of a Mach-O
					}
				}
			}
			else {
				machHeaders.add(new MachHeader(wrapper));
				machStarts.add(Integer.toUnsignedLong(fatarch.getOffset()));
				machSizes.add(Integer.toUnsignedLong(fatarch.getSize()));
			}
		}
	}

	public int getMagic() {
		return magic;
	}

	public int getFatArchitectureCount() {
		return nfat_arch;
	}

	public List<FatArch> getArchitectures() {
		return architectures;
	}

	public List<MachHeader> getMachHeaders() {
		return machHeaders;
	}

	public List<Long> getMachStarts() {
		return machStarts;
	}

	public List<Long> getMachSizes() {
		return machSizes;
	}
}
