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

package ghidra.util.bytesearch.bytepatternsearch;

/**
 * This class handles search configurations for Ghidra's Byte Pattern Searcher which dictate the
 * types of data manipulations performed by {@link BpsTransformationEngine} required prior to search
 * submission.
 * <P>
 * The design of the Byte pattern Searcher and its supporting sub-capabilities and classes can be
 * found in the "Search For Byte Patterns" page in the help viewer.
 * <P>
 * Supported data manipulations are found in {@link BpsTransformationEngine}.
 * <P>
 * Search configurations determine byte preparation manipulations prior to search submission.
 */
class BpsConfig {

	private boolean isSearchBE;
	private boolean isSearchLE;
	private boolean extendPattern; // Zero-extend patterns to fill larger word sizes
	private int programWordSize;

	/**
	 * Default constructor initializing standard search settings; primarily used for search patterns
	 * which are 8 bits. Patterns of this size will not need splitting nor will they need to be
	 * manipulated to be LE as endianness of a pattern this size does not change the pattern.
	 * 
	 * @param isByteExtension choice to zero-extend patterns to fit the word size of the program
	 * @param programWordSize word size of the program
	 */
	BpsConfig(int programWordSize, boolean isByteExtension) {
		this.programWordSize = programWordSize;
		this.extendPattern = isByteExtension;
	}

	/**
	 * Constructor for handling search settings for patterns greater than 8 bits in size.
	 * 
	 * @param programWordSize word size of the program
	 * @param isByteExtension choice to zero-extend patterns to fit the word size of the program
	 * @param isSearchBE choice to perform Big Endian search
	 * @param isSearchLE choice to perform Little Endian search
	 */
	public BpsConfig(int programWordSize, boolean isByteExtension,
			boolean isSearchBE, boolean isSearchLE) {
		this(programWordSize, isByteExtension);
		this.isSearchBE = isSearchBE;
		this.isSearchLE = isSearchLE;
	}

	/**
	 * {@return big endian choice}
	 */
	boolean isSearchBE() {
		return this.isSearchBE;
	}

	/**
	 * {@return little endian choice}
	 */
	boolean isSearchLE() {
		return this.isSearchLE;
	}

	/**
	 * Search for patterns which have been zero-padded to fill the word size of the program.
	 * <P>
	 * <B>Note:</B> Quantization of word sizes is performed - <I>Example</I>: if the byte pattern's
	 * word size is 16 (Word) but the program's word size is 64 (QWord), choosing to extend the data
	 * type will produce 2 additional byte arrays, zero-padded to 32 (DWord) and 64 (QWord).
	 * 
	 * @return extend pattern choice
	 */
	boolean isExtendPattern() {
		return this.extendPattern;
	}

	/**
	 * {@return word size of the program}
	 */
	int getProgramWordSize() {
		return this.programWordSize;
	}
}
