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
package ghidra.pcode.emu.elf;

import java.util.Objects;
import java.util.stream.Stream;

import ghidra.app.util.bin.format.elf.ElfProgramHeaderType;
import ghidra.program.model.address.*;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;

public class ElfHeaderReader {
	private final Program program;
	private final AddressSpace ram;

	private final Address elfBase;
	private final Data elfHdr;
	private final long elfPhoff;
	private final Data elfPhdrs;
	private final int elfPhnum;

	public ElfHeaderReader(Program program) {
		this.program = program;

		ram = program.getAddressFactory().getDefaultAddressSpace();
		AddressSet ramBlocks =
			program.getMemory().intersectRange(ram.getMinAddress(), ram.getMaxAddress());
		elfBase = ramBlocks.getMinAddress();
		elfHdr = program.getListing().getDefinedDataAt(elfBase);
		elfPhoff = getValueAsLong(getComponentNamed(elfHdr, "e_phoff"));
		elfPhdrs = program.getListing().getDefinedDataAt(elfBase.add(elfPhoff));
		elfPhnum = (int) getValueAsLong(getComponentNamed(elfHdr, "e_phnum"));
	}

	private static Data getComponentNamed(Data data, String name) {
		if (!(data.getDataType() instanceof Composite type)) {
			throw new IllegalArgumentException("Data %s is not a composite type".formatted(data));
		}
		DataTypeComponent typeComp = Stream.of(type.getComponents())
				.filter(c -> Objects.equals(c.getFieldName(), name))
				.findFirst()
				.orElseThrow();
		Data dataComp = data.getComponent(typeComp.getOrdinal());
		return dataComp;
	}

	private static long getValueAsLong(Data data) {
		return switch (data.getValue()) {
			case Long l -> l;
			case Scalar s -> s.getValue();
			case Address a -> a.getOffset();
			default -> throw new IllegalArgumentException(
				"Unrecognized type: %s".formatted(data.getValueClass()));
		};
	}

	private static Address getValueAsAddress(AddressSpace space, Data data) {
		return switch (data.getValue()) {
			case Long l -> space.getAddress(l);
			case Scalar s -> space.getAddress(s.getUnsignedValue());
			case Address a -> a;
			default -> throw new IllegalArgumentException(
				"Unrecognized type: %s".formatted(data.getValueClass()));
		};
	}

	private static String getStringValue(Data data) {
		return switch (data.getValue()) {
			case String s -> s;
			default -> throw new IllegalArgumentException(
				"Value is not a string: %s".formatted(data.getValueClass()));
		};
	}

	/**
	 * {@return the image base as derived from the header contents}
	 */
	public Address getNominalImageBase() {
		ElfProgramHeaderReader firstLoad = findProgramHeaderByType(ElfProgramHeaderType.PT_LOAD);
		if (firstLoad == null) {
			throw new IllegalStateException("No loadable section?");
		}
		return firstLoad.getVirtualAddress();
	}

	/**
	 * {@return the image base as it was loaded by Ghidra}
	 */
	public Address getLoadedImageBase() {
		return elfBase;
	}

	public long getLoadedImageShift() {
		return getLoadedImageBase().subtract(getNominalImageBase());
	}

	public long getProgramHeadersOffset() {
		return elfPhoff;
	}

	public Address getProgramHeadersAddress() {
		return elfBase.add(elfPhoff);
	}

	public long getProgramHeadersCount() {
		return getValueAsLong(getComponentNamed(elfHdr, "e_phnum"));
	}

	public long getProgramHeaderEntrySize() {
		return getValueAsLong(getComponentNamed(elfHdr, "e_phentsize"));
	}

	public Address getNominalEntry() {
		return getValueAsAddress(ram, getComponentNamed(elfHdr, "e_entry"));
	}

	class ElfProgramHeaderReader {
		private final Data elfPhdr;

		public ElfProgramHeaderReader(Data elfPhdr) {
			this.elfPhdr = elfPhdr;
		}

		public Address getVirtualAddress() {
			return getValueAsAddress(ram, getComponentNamed(elfPhdr, "p_vaddr"));
		}
	}

	public ElfProgramHeaderReader findProgramHeaderByType(ElfProgramHeaderType type) {
		for (int i = 0; i < elfPhnum; i++) {
			Data elfPhdr = elfPhdrs.getComponent(i);
			long pType = getValueAsLong(getComponentNamed(elfPhdr, "p_type"));
			if (type.value == pType) {
				return new ElfProgramHeaderReader(elfPhdr);
			}
		}
		return null;
	}

	public String getInterpreter() {
		ElfProgramHeaderReader phdrInterp = findProgramHeaderByType(ElfProgramHeaderType.PT_INTERP);
		if (phdrInterp == null) {
			return null;
		}
		Data interpStr = program.getListing().getDataAt(phdrInterp.getVirtualAddress());
		if (interpStr == null) {
			throw new IllegalStateException(
				"PT_INTERP program header's vaddr must point to a String Data unit");
		}
		return getStringValue(interpStr);
	}
}
