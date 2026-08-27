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
 * A helper class to build up the potentially complicated {@link BpsConfig}.
 * <P>
 * Manage the generation of a search configuration for use by Ghidra's Byte Pattern Search
 * capability.
 * <P>
 * The design of the Byte pattern Searcher and its supporting sub-capabilities and classes can be
 * found in the "Search For Byte Patterns" page in the help viewer.
 */
public class BpsConfigBuilder {

	private int programWordSize;
	private boolean isByteExtension;
	private boolean littleEndianSearch;
	private boolean bigEndianSearch = true;

	/**
	 * Constructor.
	 * 
	 * @param programWordSize the word size of the program; must be greater than 0
	 */
	public BpsConfigBuilder(int programWordSize) {

		if (programWordSize <= 0) {
			throw new IllegalArgumentException("Invalid program word size: " + programWordSize);
		}

		this.programWordSize = programWordSize;
	}

	/**
	 * Specify whether to perform a zero-extension of byte patterns to fit the program word size if
	 * the pattern's word size is smaller than the program's.
	 * <p>
	 * A true setting will perform quantization of sizes to build out the pattern's word size
	 * iteratively until it fills the program's word size. See {@link BpsConfig} for details.
	 * 
	 * @param isByteExtension true signals to zero-extend byte patterns to fill program word size
	 * 
	 * @return this builder instance
	 */
	public BpsConfigBuilder setPerformExtension(boolean isByteExtension) {
		this.isByteExtension = isByteExtension;
		return this;
	}

	/**
	 * Specify whether to search for patterns as Little Endian.
	 * 
	 * @param isLeSearch true signals the transformation of patterns to be LE prior to
	 *            search
	 * 
	 * @return this builder instance
	 */
	public BpsConfigBuilder setLittleEndianSearch(boolean isLeSearch) {
		this.littleEndianSearch = isLeSearch;
		return this;
	}

	/**
	 * Specify whether to search for patterns as Big Endian. Default is true.
	 * 
	 * @param isBeSearch true signals patterns to be searched as BE (their assumed default
	 *            endianness)
	 * 
	 * @return this builder instance
	 */
	public BpsConfigBuilder setBigEndianSearch(boolean isBeSearch) {
		this.bigEndianSearch = isBeSearch;
		return this;
	}

	/**
	 * Builds the final {@link BpsConfig}.
	 * @return the new search configuration
	 */
	public BpsConfig build() {

		// Default search configuration does not perform splitting 
		return new BpsConfig(this.programWordSize, this.isByteExtension,
			this.bigEndianSearch, this.littleEndianSearch);
	}
}
