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

import static ghidra.app.util.bin.format.elf.extend.ARM_ElfProgramHeaderConstants.*;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;

/**
 * Reads which variant of the AAPCS an ARM ELF image explicitly states it was built for: the
 * base (soft-float) variant, which passes floating-point values in core registers, or the VFP
 * variant.
 * <p>
 * An EABI version 5 executable or shared object states it with the
 * {@code EF_ARM_ABI_FLOAT_SOFT}/{@code EF_ARM_ABI_FLOAT_HARD} header flags ("ELF for the Arm
 * Architecture"), and any ARM ELF file with the file-scope {@code Tag_ABI_VFP_args} build
 * attribute, where an omitted public tag means 0, the base variant ("Addenda to, and Errata in,
 * the ABI for the Arm Architecture", Build Attributes).  Images whose header states neither
 * variant are not assumed to use the base variant.  Contradictory, unsupported or malformed
 * statements state nothing.
 */
class ARM_ElfFloatAbi {

	private enum Abi {
		NONE, BASE, VFP, INVALID
	}

	private static final long TAG_FILE = 1;
	private static final long TAG_SECTION = 2;
	private static final long TAG_SYMBOL = 3;
	private static final long TAG_CPU_RAW_NAME = 4;
	private static final long TAG_CPU_NAME = 5;
	private static final long TAG_ABI_VFP_ARGS = 28;
	private static final long TAG_COMPATIBILITY = 32;
	private static final long TAG_NODEFAULTS = 64;

	private ARM_ElfFloatAbi() {
	}

	/**
	 * Returns true if the image explicitly states the base (soft-float) procedure-call standard
	 * and nothing contradicts it.
	 * @param elf the ELF header, with its section headers parsed
	 * @return true if the image states the base procedure-call standard
	 */
	static boolean isSoftFloat(ElfHeader elf) {
		return combine(fromFlags(elf), fromAttributes(elf)) == Abi.BASE;
	}

	private static Abi fromFlags(ElfHeader elf) {
		int flags = elf.e_flags();
		if (!(elf.isExecutable() || elf.isSharedObject()) || (flags & EF_ARM_EABIMASK) >>> 24 < 5) {
			return Abi.NONE;
		}
		switch (flags & (EF_ARM_ABI_FLOAT_SOFT | EF_ARM_ABI_FLOAT_HARD)) {
			case EF_ARM_ABI_FLOAT_SOFT:
				return Abi.BASE;
			case EF_ARM_ABI_FLOAT_HARD:
				return Abi.VFP;
			case EF_ARM_ABI_FLOAT_SOFT | EF_ARM_ABI_FLOAT_HARD:
				return Abi.INVALID;
			default:
				return Abi.NONE;
		}
	}

	private static Abi fromAttributes(ElfHeader elf) {
		Abi abi = Abi.NONE;
		int type = ARM_ElfExtension.SHT_ARM_ATTRIBUTES.value;
		for (ElfSectionHeader section : elf.getSections(type)) {
			Abi sectionAbi;
			try {
				sectionAbi = readSection(elf.getByteProvider(), section, elf.isLittleEndian());
			}
			catch (IOException e) {
				sectionAbi = Abi.INVALID;
			}
			abi = combine(abi, sectionAbi);
		}
		return abi;
	}

	private static Abi combine(Abi a, Abi b) {
		if (a == Abi.NONE) {
			return b;
		}
		if (b == Abi.NONE || a == b) {
			return a;
		}
		return Abi.INVALID;
	}

	/**
	 * Reads the file-scope Tag_ABI_VFP_args statement of one attributes section, aggregated over
	 * all of its "aeabi" file-scope records.  Every read is bounded by the enclosing
	 * subsection, and any malformed structure is an {@link IOException}.
	 */
	private static Abi readSection(ByteProvider provider, ElfSectionHeader section,
			boolean littleEndian) throws IOException {
		long offset = section.getOffset();
		long size = section.getSize();
		if (size > provider.length() - offset) {
			return Abi.INVALID;
		}
		BinaryReader reader =
			new BinaryReader(new ByteProviderWrapper(provider, offset, size), littleEndian);
		if (reader.readNextUnsignedByte() != 'A') {
			return Abi.INVALID;
		}
		boolean aeabi = false;
		boolean noDefaults = false;
		Set<Long> vfpArgs = new HashSet<>();
		while (reader.hasNext()) {
			long start = reader.getPointerIndex();
			long length = reader.readNextUnsignedInt();
			if (start + length > reader.length()) {
				return Abi.INVALID;
			}
			BinaryReader subsection = bounded(reader, start + 4, start + length);
			if (subsection.readNextAsciiString().equals("aeabi")) {
				aeabi = true;
				while (subsection.hasNext()) {
					long scopeStart = subsection.getPointerIndex();
					long scopeTag = LEB128Info.unsigned(subsection).asLong();
					long scopeSize = subsection.readNextUnsignedInt();
					long scopeEnd = scopeStart + scopeSize;
					if (scopeEnd < subsection.getPointerIndex() || scopeEnd > subsection.length()) {
						return Abi.INVALID;
					}
					if (scopeTag == TAG_FILE) {
						long body = subsection.getPointerIndex();
						noDefaults |= readFileScope(bounded(subsection, body, scopeEnd), vfpArgs);
					}
					else if (scopeTag != TAG_SECTION && scopeTag != TAG_SYMBOL) {
						return Abi.INVALID;
					}
					subsection.setPointerIndex(scopeEnd);
				}
			}
			reader.setPointerIndex(start + length);
		}
		if (!aeabi) {
			return Abi.NONE;
		}
		if (vfpArgs.isEmpty()) {
			return noDefaults ? Abi.NONE : Abi.BASE;
		}
		if (vfpArgs.size() > 1) {
			return Abi.INVALID;
		}
		long value = vfpArgs.iterator().next();
		if (value == 0) {
			return Abi.BASE;
		}
		if (value == 1) {
			return Abi.VFP;
		}
		// 3: no floating-point parameters or results, either variant applies
		return value == 3 ? Abi.NONE : Abi.INVALID;
	}

	/**
	 * Collects the Tag_ABI_VFP_args values of a file-scope record.
	 * @return true if the record carries Tag_nodefaults
	 */
	private static boolean readFileScope(BinaryReader scope, Set<Long> vfpArgs)
			throws IOException {
		boolean noDefaults = false;
		while (scope.hasNext()) {
			long tag = LEB128Info.unsigned(scope).asLong();
			if (tag == 0) {
				throw new IOException("Reserved attribute tag 0");
			}
			if (tag == TAG_COMPATIBILITY) {
				LEB128Info.unsigned(scope);
				scope.readNextAsciiString();
			}
			else if (tag == TAG_CPU_RAW_NAME || tag == TAG_CPU_NAME ||
				(Long.compareUnsigned(tag, TAG_COMPATIBILITY) > 0 && (tag & 1) != 0)) {
				scope.readNextAsciiString();
			}
			else {
				long value = LEB128Info.unsigned(scope).asLong();
				if (tag == TAG_ABI_VFP_ARGS) {
					vfpArgs.add(value);
				}
				else if (tag == TAG_NODEFAULTS) {
					noDefaults = true;
				}
			}
		}
		return noDefaults;
	}

	private static BinaryReader bounded(BinaryReader reader, long start, long end) {
		ByteProvider range = new ByteProviderWrapper(reader.getByteProvider(), start, end - start);
		return new BinaryReader(range, reader.isLittleEndian());
	}
}
