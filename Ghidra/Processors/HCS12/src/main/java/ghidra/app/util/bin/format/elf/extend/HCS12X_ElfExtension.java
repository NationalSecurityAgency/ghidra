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
package ghidra.app.util.bin.format.elf.extend;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;

public class HCS12X_ElfExtension extends ElfExtension {

	// Elf Program Header Extensions
	public static final ElfProgramHeaderType PT_HCS12_ARCHEXT =
		new ElfProgramHeaderType(0x70000000, "PT_HCS12X_ARCHEXT", "HCS12X extension");

	// Elf Section Header Extensions
	public static final ElfSectionHeaderType SHT_HCS12_ATTRIBUTES =
		new ElfSectionHeaderType(0x70000003, "SHT_AHCS12_ATTRIBUTES", "Attribute section");

	@Override
	public boolean canHandle(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_68HC12;
	}

	@Override
	public boolean canHandle(ElfLoadHelper elfLoadHelper) {
		Language language = elfLoadHelper.getProgram().getLanguage();
		return canHandle(elfLoadHelper.getElfHeader()) &&
			"HCS12".equals(language.getProcessor().toString());
	}

	@Override
	public String getDataTypeSuffix() {
		return "_HCS12";
	}

	@Override
	public Address getPreferredSegmentAddress(ElfLoadHelper elfLoadHelper,
			ElfProgramHeader elfProgramHeader) {

		AddressSpace space = getPreferredSegmentAddressSpace(elfLoadHelper, elfProgramHeader);

		Program program = elfLoadHelper.getProgram();

		long addrWordOffset = elfProgramHeader.getVirtualAddress();

		if (space == program.getAddressFactory().getDefaultAddressSpace()) {
			addrWordOffset += elfLoadHelper.getImageBaseWordAdjustmentOffset();
		}

		addrWordOffset = hcs12TranslatePagedAddress(addrWordOffset);

		return space.getTruncatedAddress(addrWordOffset, true);
	}

	@Override
	public Address getPreferredSectionAddress(ElfLoadHelper elfLoadHelper,
			ElfSectionHeader elfSectionHeader) {

		Program program = elfLoadHelper.getProgram();

		AddressSpace space = getPreferredSectionAddressSpace(elfLoadHelper, elfSectionHeader);

		long addrWordOffset = elfSectionHeader.getAddress();

		if (space == program.getAddressFactory().getDefaultAddressSpace()) {
			addrWordOffset += elfLoadHelper.getImageBaseWordAdjustmentOffset();
		}

		addrWordOffset = hcs12TranslatePagedAddress(addrWordOffset);

		return space.getTruncatedAddress(addrWordOffset, true);
	}

	private long hcs12TranslatePagedAddress(long addrWordOffset) {

		long page = (addrWordOffset >> 16) & 0xff;

		long addr = addrWordOffset & 0xffff;

		// Register address
		if ((addr & 0xfC00) == 0x0) {
			return addr;
		}

		// EPage address
		if ((addr & 0xfc00) == 0x800) {
			return 0x100000 | ((page << 10) | (addr & 0x3ff));
		}

		// EPage FF fixed address
		if ((addr & 0xfc00) == 0xC00) {
			return (0x4FF << 10) | (addr & 0x3ff);
		}

		// RPage address
		if ((addr & 0xf000) == 0x1000) {
			return (page << 12) | (addr & 0xfff);
		}

		// RPage FE fixed address
		if ((addr & 0xf000) == 0x2000) {
			return (0xFE << 12) | (addr & 0xfff);
		}

		// RPage FF fixed address
		if ((addr & 0xf000) == 0x3000) {
			return (0xFF << 12) | (addr & 0xfff);
		}

		// PPage FD fixed address
		if ((addr & 0xc000) == 0x4000) {
			return 0x400000 | (0xFD << 14) | (addr & 0x3fff);
		}

		// PPage address
		if ((addr & 0xc000) == 0x8000) {
			return 0x400000 | (page << 14) | (addr & 0x3fff);
		}

		// PPage FF fixed address
		if ((addr & 0xc000) == 0xC000) {
			return 0x400000 | (0xFF << 14) | (addr & 0x3fff);
		}

		return addr;
	}

	@Override
	public Address evaluateElfSymbol(ElfLoadHelper elfLoadHelper, ElfSymbol elfSymbol,
			Address address, boolean isExternal) {

		if (isExternal) {
			return address;
		}

		String symName = elfSymbol.getNameAsString();

		long laddr = address.getOffset();

		laddr = hcs12TranslatePagedAddress(laddr);

		Address mappedAddr = address.getNewAddress(laddr);

		return mappedAddr;
	}

}
