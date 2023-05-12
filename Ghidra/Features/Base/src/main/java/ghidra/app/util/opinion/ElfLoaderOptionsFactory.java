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

import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.extend.ElfExtensionFactory;
import ghidra.app.util.bin.format.elf.extend.ElfLoadAdapter;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.util.NumericUtilities;
import ghidra.util.StringUtilities;

public class ElfLoaderOptionsFactory {

	public static final String PERFORM_RELOCATIONS_NAME = "Perform Symbol Relocations";
	static final boolean PERFORM_RELOCATIONS_DEFAULT = true;

	// NOTE: Using too large of an image base can cause problems for relocation processing
	// for some language scenarios which utilize 32-bit relocations.  This may be due to
	// an assumed virtual memory of 32-bits.

	public static final String IMAGE_BASE_OPTION_NAME = "Image Base";
	public static final long IMAGE_BASE_DEFAULT = 0x00010000;
	public static final long IMAGE64_BASE_DEFAULT = 0x00100000L;
	
	public static final String IMAGE_DATA_IMAGE_BASE_OPTION_NAME = "Data Image Base";

	public static final String INCLUDE_OTHER_BLOCKS = "Import Non-Loaded Data";// as OTHER overlay blocks
	static final boolean INCLUDE_OTHER_BLOCKS_DEFAULT = true;

	public static final String DISCARDABLE_SEGMENT_SIZE_OPTION_NAME =
		"Max Zero-Segment Discard Size";

	// Maximum length of discardable segment
	// If program contains section headers, any zeroed segment smaller than this size
	// will be eligible for removal.
	private static final int DEFAULT_DISCARDABLE_SEGMENT_SIZE = 0xff;

	private ElfLoaderOptionsFactory() {
	}

	static void addOptions(List<Option> options, ByteProvider provider, LoadSpec loadSpec)
			throws ElfException, LanguageNotFoundException {

		// NOTE: add-to-program is not supported

		options.add(new Option(PERFORM_RELOCATIONS_NAME, PERFORM_RELOCATIONS_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-applyRelocations"));

		ElfHeader elf = new ElfHeader(provider, null);

		long imageBase = elf.findImageBase();
		if (imageBase == 0 && (elf.isRelocatable() || elf.isSharedObject())) {
			imageBase = elf.is64Bit() ? IMAGE64_BASE_DEFAULT : IMAGE_BASE_DEFAULT;
		}
		Language language = loadSpec.getLanguageCompilerSpec().getLanguage();
		AddressSpace defaultSpace = language.getDefaultSpace();

		String hexValueStr = getBaseAddressOffsetString(imageBase, defaultSpace);
		options.add(new Option(IMAGE_BASE_OPTION_NAME, hexValueStr, String.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-imagebase"));
		
		if (includeDataImageBaseOption(elf, language)) {
			long minDataImageBase = getRecommendedMinimumDataImageBase(elf, language);
			hexValueStr =
				getBaseAddressOffsetString(minDataImageBase, language.getDefaultDataSpace());
			options.add(new Option(IMAGE_DATA_IMAGE_BASE_OPTION_NAME, hexValueStr, String.class,
				Loader.COMMAND_LINE_ARG_PREFIX + "-dataImageBase"));
		}

		options.add(new Option(INCLUDE_OTHER_BLOCKS, INCLUDE_OTHER_BLOCKS_DEFAULT, Boolean.class,
			Loader.COMMAND_LINE_ARG_PREFIX + "-includeOtherBlocks"));

		options.add(
			new Option(DISCARDABLE_SEGMENT_SIZE_OPTION_NAME, DEFAULT_DISCARDABLE_SEGMENT_SIZE,
				Integer.class, Loader.COMMAND_LINE_ARG_PREFIX + "-maxSegmentDiscardSize"));

		ElfLoadAdapter extensionAdapter = ElfExtensionFactory.getLoadAdapter(elf);
		if (extensionAdapter != null) {
			extensionAdapter.addLoadOptions(elf, options);
		}

	}
	
	private static boolean includeDataImageBaseOption(ElfHeader elf, Language language) {
		// only include option if all segments and section have a 0 address
		AddressSpace defaultSpace = language.getDefaultSpace();
		AddressSpace defaultDataSpace = language.getDefaultDataSpace();
		if (defaultDataSpace.equals(defaultSpace)) {
			return false;
		}
		return elf.isRelocatable() && elf.getImageBase() == 0;
	}
	
	private static long getRecommendedMinimumDataImageBase(ElfHeader elf, Language language) {
		
		String minDataOffset =
			language.getProperty(GhidraLanguagePropertyKeys.MINIMUM_DATA_IMAGE_BASE);
		if (minDataOffset != null) {
			return NumericUtilities.parseHexLong(minDataOffset);
		}
		
		AddressSpace defaultDataSpace = language.getDefaultDataSpace();
		int unitSize = defaultDataSpace.getAddressableUnitSize();
		
		// logic assumes memory mapped registers reside at low-end addresses (e.g., 0)
		long minOffset = 0;
		for (Register reg : language.getRegisters()) {
			Address addr = reg.getAddress();
			if (defaultDataSpace.equals(addr.getAddressSpace())) {
				long offset = addr.getOffset();
				if (offset < 0) {
					continue;
				}
				offset += reg.getMinimumByteSize();
				if (offset > minOffset) {
					minOffset = offset;
				}
			}
		}
		// set minimum align
		int align = 16 * unitSize;
		minOffset += align - (minOffset % align);
		return minOffset / unitSize;
	}

	private static String getBaseAddressOffsetString(long imageBase, AddressSpace space) {
		long maxOffset = space.getMaxAddress().getAddressableWordOffset();
		while (Long.compareUnsigned(imageBase, maxOffset) > 0) {
			imageBase >>>= 4;
		}
		String baseOffsetStr = Long.toHexString(imageBase);
		int minNibbles = Math.min(8, space.getSize() / 4);
		int baseOffsetStrLen = baseOffsetStr.length();
		if (baseOffsetStrLen < minNibbles) {
			baseOffsetStr =
				StringUtilities.pad(baseOffsetStr, '0', minNibbles - baseOffsetStrLen);
		}
		return baseOffsetStr;
	}

	static String validateOptions(LoadSpec loadSpec, List<Option> options) {
		Language language;
		try {
			language = loadSpec.getLanguageCompilerSpec().getLanguage();
		} catch (LanguageNotFoundException e) {
			throw new RuntimeException(e);
		}
		for (Option option : options) {
			String name = option.getName();
			if (name.equals(PERFORM_RELOCATIONS_NAME)) {
				if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
					return "Invalid type for option: " + name + " - " + option.getValueClass();
				}
			}
			else if (name.equals(INCLUDE_OTHER_BLOCKS)) {
				if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
					return "Invalid type for option: " + name + " - " + option.getValueClass();
				}
			}
			else if (name.equals(IMAGE_BASE_OPTION_NAME)) {
				String err = validateAddressSpaceOffsetOption(option, language.getDefaultSpace());
				if (err != null) {
					return err;
				}
			}
			else if (name.equals(IMAGE_DATA_IMAGE_BASE_OPTION_NAME)) {
				String err =
					validateAddressSpaceOffsetOption(option, language.getDefaultDataSpace());
				if (err != null) {
					return err;
				}
			}
			else if (name.equals(DISCARDABLE_SEGMENT_SIZE_OPTION_NAME)) {
				if (!Integer.class.isAssignableFrom(option.getValueClass())) {
					return "Invalid type for option: " + name + " - " + option.getValueClass();
				}
				int val = (Integer) option.getValue();
				if (val < 0 || val > DEFAULT_DISCARDABLE_SEGMENT_SIZE) {
					return "Option value out-of-range: " + name + " (0.." +
						DEFAULT_DISCARDABLE_SEGMENT_SIZE + ")";
				}
			}
		}
		return null;
	}

	private static String validateAddressSpaceOffsetOption(Option option, AddressSpace space) {
		String name = option.getName();
		if (!String.class.isAssignableFrom(option.getValueClass())) {
			return "Invalid type for option: " + name + " - " + option.getValueClass();
		}
		String value = (String) option.getValue();
		try {
			space.getAddress(Long.parseUnsignedLong(value, 16), true);// verify valid address
		}
		catch (NumberFormatException e) {
			return "Invalid " + name + " - expecting hexidecimal address offset";
		}
		catch (AddressOutOfBoundsException e) {
			return "Invalid " + name + " - " + e.getMessage();
		}
		return null;
	}

	static boolean performRelocations(List<Option> options) {
		return OptionUtils.getOption(PERFORM_RELOCATIONS_NAME, options,
			PERFORM_RELOCATIONS_DEFAULT);
	}

	static boolean includeOtherBlocks(List<Option> options) {
		return OptionUtils.getOption(INCLUDE_OTHER_BLOCKS, options, INCLUDE_OTHER_BLOCKS_DEFAULT);
	}

	static boolean hasImageBaseOption(List<Option> options) {
		return OptionUtils.containsOption(IMAGE_BASE_OPTION_NAME, options);
	}

	public static String getImageBaseOption(List<Option> options) {
		return OptionUtils.getOption(IMAGE_BASE_OPTION_NAME, options, (String) null);
	}
	
	public static String getDataImageBaseOption(List<Option> options) {
		return OptionUtils.getOption(IMAGE_DATA_IMAGE_BASE_OPTION_NAME, options, (String) null);
	}

	public static int getMaxSegmentDiscardSize(List<Option> options) {
		return OptionUtils.getOption(DISCARDABLE_SEGMENT_SIZE_OPTION_NAME, options,
			DEFAULT_DISCARDABLE_SEGMENT_SIZE);
	}

}
