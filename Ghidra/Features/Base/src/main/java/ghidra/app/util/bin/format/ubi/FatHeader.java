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

import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.coff.CoffException;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveHeader;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveMemberHeader;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a fat_header structure.
 * 
 * @see <a href="https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/fat.h.auto.html">mach-o/fat.h</a> 
 */
public class FatHeader {
	public final static int FAT_MAGIC = 0xcafebabe;
	public final static int FAT_CIGAM = 0xbebafeca;

    private int magic;
	private int nfat_arch;
	private List<FatArch> architectures = new ArrayList<FatArch>();
	private List<MachHeader> machHeaders = new ArrayList<MachHeader>();

    public static FatHeader createFatHeader(GenericFactory factory, ByteProvider provider)
            throws IOException, UbiException, MachException {
        FatHeader fatHeader = (FatHeader) factory.create(FatHeader.class);
        fatHeader.initFatHeader(factory, provider);
        return fatHeader;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public FatHeader() {}

	private void initFatHeader(GenericFactory factory, ByteProvider provider) throws IOException, UbiException, MachException {
		FactoryBundledWithBinaryReader reader = new FactoryBundledWithBinaryReader(factory, provider, false/*always big endian*/);

		magic = reader.readNextInt();

		if (magic != FAT_MAGIC && magic != FAT_CIGAM) {
			throw new UbiException("Invalid UBI file.");
		}

		nfat_arch = reader.readNextInt();
		if (nfat_arch > 0x1000 || nfat_arch < 0) {
			throw new UbiException("Invalid UBI file.");
		}

		for (int i = 0 ; i < nfat_arch ; ++i) {
			architectures.add(FatArch.createFatArch(reader));
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
						machHeaders.add(MachHeader.createMachHeader(factory, wrapper));
					}
					catch (MachException e) {
						// Could be __.SYMDEF archive member instead of a Mach-O
					}
				}
			}
			else {
				machHeaders.add(MachHeader.createMachHeader(factory, wrapper));
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
}
