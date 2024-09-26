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
package ghidra.features.base.memsearch.gui;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.features.base.memsearch.bytesource.SearchRegion;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;

/**
 * Immutable container for all the relevant search settings.
 */
public class SearchSettings {
	private final SearchFormat searchFormat;
	private final Set<SearchRegion> selectedRegions;
	private final int alignment;
	private final boolean bigEndian;
	private final boolean caseSensitive;
	private final boolean useEscapeSequences;
	private final boolean includeInstructions;
	private final boolean includeDefinedData;
	private final boolean includeUndefinedData;
	private final boolean isDecimalUnsigned;
	private final int decimalByteSize;
	private final Charset charset;

	public SearchSettings() {
		this(SearchFormat.HEX, false, false, false, true, true, true, false, 4, 1, new HashSet<>(),
			StandardCharsets.US_ASCII);
	}

	//@formatter:off
	private SearchSettings(
			SearchFormat format, 
			boolean bigEndian, 
			boolean caseSensitive,
			boolean useEscapeSequences,
			boolean includeInstructions,
			boolean includeDefinedData,
			boolean includeUndefinedData,
			boolean isDecimalUnsigned,
			int decimalByteSize,
			int alignment,
			Set<SearchRegion> selectedRegions,
			Charset charset) {
		
		this.searchFormat = format;
		this.bigEndian = bigEndian;
		this.caseSensitive = caseSensitive;
		this.useEscapeSequences = useEscapeSequences;
		this.includeInstructions = includeInstructions;
		this.includeDefinedData = includeDefinedData;
		this.includeUndefinedData = includeUndefinedData;
		this.alignment = alignment;
		this.decimalByteSize = decimalByteSize;
		this.isDecimalUnsigned = isDecimalUnsigned;
		this.selectedRegions = Collections.unmodifiableSet(new HashSet<>(selectedRegions));
		this.charset = charset;

	}
	//@formatter:on

	/**
	 * Returns the {@link SearchFormat} to be used to parse the input text.
	 * @return the search format to be used to parse the input text
	 */
	public SearchFormat getSearchFormat() {
		return searchFormat;
	}

	/**
	 * Creates a copy of this settings object, but using the given search format.
	 * @param format the new search format
	 * @return a new search settings that is the same as this settings except for the format
	 */
	public SearchSettings withSearchFormat(SearchFormat format) {
		if (this.searchFormat == format) {
			return this;
		}
		return new SearchSettings(format, bigEndian, caseSensitive,
			useEscapeSequences, includeInstructions, includeDefinedData, includeUndefinedData,
			isDecimalUnsigned, decimalByteSize, alignment, selectedRegions, charset);
	}

	public boolean isBigEndian() {
		return bigEndian;
	}

	public SearchSettings withBigEndian(boolean isBigEndian) {
		if (this.bigEndian == isBigEndian) {
			return this;
		}
		return new SearchSettings(searchFormat, isBigEndian, caseSensitive,
			useEscapeSequences, includeInstructions, includeDefinedData, includeUndefinedData,
			isDecimalUnsigned, decimalByteSize, alignment, selectedRegions, charset);
	}

	public SearchSettings withStringCharset(Charset stringCharset) {
		if (this.charset == stringCharset) {
			return this;
		}
		return new SearchSettings(searchFormat, bigEndian, caseSensitive,
			useEscapeSequences, includeInstructions, includeDefinedData, includeUndefinedData,
			isDecimalUnsigned, decimalByteSize, alignment, selectedRegions, stringCharset);
	}

	public Charset getStringCharset() {
		return charset;
	}

	public boolean useEscapeSequences() {
		return useEscapeSequences;
	}

	public SearchSettings withUseEscapeSequence(boolean b) {
		if (this.useEscapeSequences == b) {
			return this;
		}
		return new SearchSettings(searchFormat, bigEndian, caseSensitive,
			b, includeInstructions, includeDefinedData, includeUndefinedData,
			isDecimalUnsigned, decimalByteSize, alignment, selectedRegions, charset);
	}

	public boolean isCaseSensitive() {
		return caseSensitive;
	}

	public SearchSettings withCaseSensitive(boolean b) {
		if (this.caseSensitive == b) {
			return this;
		}
		return new SearchSettings(searchFormat, bigEndian, b,
			useEscapeSequences, includeInstructions, includeDefinedData, includeUndefinedData,
			isDecimalUnsigned, decimalByteSize, alignment, selectedRegions, charset);
	}

	public boolean isDecimalUnsigned() {
		return isDecimalUnsigned;
	}

	public SearchSettings withDecimalUnsigned(boolean b) {
		if (this.isDecimalUnsigned == b) {
			return this;
		}
		return new SearchSettings(searchFormat, bigEndian, caseSensitive,
			useEscapeSequences, includeInstructions, includeDefinedData, includeUndefinedData,
			b, decimalByteSize, alignment, selectedRegions, charset);
	}

	public int getDecimalByteSize() {
		return decimalByteSize;
	}

	public SearchSettings withDecimalByteSize(int byteSize) {
		if (this.decimalByteSize == byteSize) {
			return this;
		}
		return new SearchSettings(searchFormat, bigEndian, caseSensitive,
			useEscapeSequences, includeInstructions, includeDefinedData, includeUndefinedData,
			isDecimalUnsigned, byteSize, alignment, selectedRegions, charset);
	}

	public boolean includeInstructions() {
		return includeInstructions;
	}

	public SearchSettings withIncludeInstructions(boolean b) {
		if (this.includeInstructions == b) {
			return this;
		}
		return new SearchSettings(searchFormat, bigEndian, caseSensitive,
			useEscapeSequences, b, includeDefinedData, includeUndefinedData,
			isDecimalUnsigned, decimalByteSize, alignment, selectedRegions, charset);
	}

	public boolean includeDefinedData() {
		return includeDefinedData;
	}

	public SearchSettings withIncludeDefinedData(boolean b) {
		if (this.includeDefinedData == b) {
			return this;
		}
		return new SearchSettings(searchFormat, bigEndian, caseSensitive,
			useEscapeSequences, includeInstructions, b, includeUndefinedData,
			isDecimalUnsigned, decimalByteSize, alignment, selectedRegions, charset);
	}

	public boolean includeUndefinedData() {
		return includeUndefinedData;
	}

	public SearchSettings withIncludeUndefinedData(boolean b) {
		if (this.includeUndefinedData == b) {
			return this;
		}

		return new SearchSettings(searchFormat, bigEndian, caseSensitive,
			useEscapeSequences, includeInstructions, includeDefinedData, b,
			isDecimalUnsigned, decimalByteSize, alignment, selectedRegions, charset);
	}

	public int getAlignment() {
		return alignment;
	}

	public SearchSettings withAlignment(int newAlignment) {
		if (this.alignment == newAlignment) {
			return this;
		}
		return new SearchSettings(searchFormat, bigEndian, caseSensitive,
			useEscapeSequences, includeInstructions, includeDefinedData, includeUndefinedData,
			isDecimalUnsigned, decimalByteSize, newAlignment, selectedRegions, charset);
	}

	public Set<SearchRegion> getSelectedMemoryRegions() {
		return selectedRegions;
	}

	public SearchSettings withSelectedRegions(Set<SearchRegion> regions) {
		if (this.selectedRegions.equals(regions)) {
			return this;
		}
		return new SearchSettings(searchFormat, bigEndian, caseSensitive,
			useEscapeSequences, includeInstructions, includeDefinedData, includeUndefinedData,
			isDecimalUnsigned, decimalByteSize, alignment, regions, charset);
	}

	public boolean isSelectedRegion(SearchRegion region) {
		return selectedRegions.contains(region);
	}

	public SearchSettings withSelectedRegion(SearchRegion region, boolean select) {
		return new SearchSettings(searchFormat, bigEndian, caseSensitive,
			useEscapeSequences, includeInstructions, includeDefinedData, includeUndefinedData,
			isDecimalUnsigned, decimalByteSize, alignment,
			createRegionSet(selectedRegions, region, select), charset);
	}

	public AddressSet getSearchAddresses(Program program) {
		AddressSet set = new AddressSet();
		for (SearchRegion memoryRegion : selectedRegions) {
			set.add(memoryRegion.getAddresses(program));
		}
		return set;
	}

	private static Set<SearchRegion> createRegionSet(Set<SearchRegion> regions,
			SearchRegion region, boolean select) {
		Set<SearchRegion> set = new HashSet<>(regions);
		if (select) {
			set.add(region);
		}
		else {
			set.remove(region);
		}
		return set;
	}

}
