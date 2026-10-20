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

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.lang.Endian;

/**
 * This class records a byte pattern's transformation in support of Ghidra's Byte Pattern Search
 * capability.
 * <P>
 * The design of the Byte pattern Searcher and its supporting sub-capabilities and classes can be
 * found in the "Search For Byte Patterns" page in the help viewer.
 * <P>
 * Indicates the structural state mutations which have been applied to a {@link BpsPattern}.
 * <P>
 * <B>NOTE</B>: Once patterns are generated, they do not change (instead, when transforming a
 * pattern, a new pattern is generated and has its own transformation record) so pattern
 * transformation records are not modifiable.
 * 
 * @param endianness of the pattern
 * @param extensionSize word size the pattern was padded to (can be null)
 * @param splitToSize word size the pattern was split to (can be null)
 * @param splitPartIndex index of the split that this pattern represents (eg. index=1 indicates the
 *            first part of a split) (can be null)
 * @param totalSplitParts total count of all parts of a split pattern (can be null)
 */
public record BpsTransformation(
		Endian endianness,
		Integer extensionSize,
		Integer splitToSize,
		Integer splitPartIndex,
		Integer totalSplitParts) {

	/**
	 * Factory method for an unmodified baseline pattern.
	 * <P>
	 * <B>NOTE</B>: All patterns prior to any transformations are safely assumed to be big endian.
	 * 
	 * @return the transformation
	 */
	public static BpsTransformation empty() {
		return new BpsTransformation(Endian.BIG, null, null, null, null);
	}

	/**
	 * {@return Creates a copy of this record that uses the Little Endian setting}
	 */
	public BpsTransformation asLittleEndian() {
		Integer padSize = extensionSize;
		Integer splitSize = splitToSize;
		Integer splitIndex = splitPartIndex;
		Integer splitParts = totalSplitParts;
		return new BpsTransformation(Endian.LITTLE, padSize, splitSize, splitIndex,
			splitParts);
	}

	@Override
	public String toString() {
		return getDescription();
	}

	/**
	 * {@return the description of the pattern's transformation history}
	 */
	public String getDescription() {
		List<String> steps = new ArrayList<>();
		steps.add("Endian: " + endianness.getDisplayName());
		if (extensionSize != null) {
			steps.add("Padded to " + extensionSize);
		}
		if (splitPartIndex != null) {
			steps.add(String.format("Split to %d Word Size | Chunk %d of %d", splitToSize,
				splitPartIndex, totalSplitParts));
		}
		return String.join(" -> ", steps);
	}

}
