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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

import ghidra.program.model.lang.Endian;

/**
 * This class performs byte pattern transformations in support of Ghidra's Byte Pattern Search
 * capability.
 * <P>
 * The design of the Byte pattern Searcher and its supporting sub-capabilities and classes can be
 * found in the "Search For Byte Patterns" page in the help viewer.
 * <P>
 * This transformer is used to prepare byte patterns parsed by the {@link BpsXmlParser} and
 * populated in {@link BpsSearchItem} objects, prior to submitting them for search.
 * <P>
 * Supported transformations are as follows:
 * <ul>
 * <li><b>Little Endian</b> - Reverse a big Endian byte array. This is determined either
 * programmatically based on the program's endianness or is user-controlled.</li>
 * <li><b>Byte Splitting</b> - If the pattern's word size is larger than the program's word
 * boundary, split the pattern to fit the boundary. This is determined programmatically and is not
 * user-controlled.</li>
 * <li><b>Byte Zero-Padding</b> - If the pattern's word size is smaller than the program's word
 * boundary, zero-pad the byte pattern to fit the program's word boundary. The decision to extend
 * bytes is user-controlled.</li>
 * </ul>
 * <P>
 * A skip list is used to allow users to skip patterns at the {@link BpsSearch} and
 * {@link BpsSearchItem} level.
 */
public class BpsTransformationEngine {

	/**
	 * Process an entire search library parsed by {@link BpsXmlParser} and populated in
	 * {@link BpsSearch} and {@link BpsSearchItem} objects in preparation for search submission.
	 * 
	 * @param searchLibrary collection of search objects
	 * @param config search preferences from user input and program details
	 * 
	 * @return All patterns prepared for search submission
	 */
	public List<BpsPattern> createPatterns(List<BpsSearch> searchLibrary, BpsConfig config) {
		return createPatterns(searchLibrary, null, config);
	}

	/**
	 * Process an entire search library parsed by {@link BpsXmlParser} and populated in
	 * {@link BpsSearch} and {@link BpsSearchItem} objects in preparation for search submission.
	 * <P>
	 * Skip over any patterns whose id's are included in a skip list.
	 * 
	 * @param searchLibrary collection of search objects
	 * @param skipIds list of {@link BpsSearch} and/or {@link BpsSearchItem} id's to skip over
	 * @param config search preferences from user input and program details
	 * 
	 * @return All patterns prepared for search submission
	 */
	public List<BpsPattern> createPatterns(List<BpsSearch> searchLibrary,
			Set<String> skipIds, BpsConfig config) {

		List<BpsPattern> results = new ArrayList<>();
		if (skipIds == null) {
			skipIds = Collections.emptySet();
		}

		for (BpsSearch search : searchLibrary) {
			if (skipIds.contains(search.getId())) {
				continue;
			}
			for (BpsSearchItem searchItem : search.getSearchItems()) {
				if (skipIds.contains(searchItem.getId())) {
					continue;
				}

				int patternWordSize = searchItem.getWordSize();
				List<BpsPattern> patterns = searchItem.getPatterns();
				List<BpsPattern> transformed = transformPatterns(patterns, config, patternWordSize);
				results.addAll(transformed);
			}
		}
		return results;
	}

	/**
	 * Transform patterns to accommodate search configurations as identified in {@link BpsConfig}.
	 * <P>
	 * Transformations are completed in the following order:
	 * <ol>
	 * <li><b>Little Endian</b> - generate the LE arrangement from the BE pattern.</li>
	 * <li><b>Byte Splitting</b> - If the pattern's word size is larger than the program's word
	 * boundary, split the pattern to fit the boundary.</li>
	 * <li><b>Byte Zero-Padding</b> - If the pattern's word size is smaller than the program's word
	 * boundary, zero-pad the byte pattern to fit the program's word boundary.</li>
	 * </ol>
	 * Generally, these transformations are determined by the program's details (endianness and word
	 * boundary), but user input may also dictate how patterns are prepared for search.
	 * <P>
	 * 
	 * @param originals collection of byte patterns for transformation
	 * @param config search configuration
	 * @param searchItemWordSize the search item word size
	 * 
	 * @return collection of transformed byte patterns
	 */
	private List<BpsPattern> transformPatterns(List<BpsPattern> originals,
			BpsConfig config, int searchItemWordSize) {

		// 1. Process endianness if needed
		// 	  Endianness does not matter and splitting is not needed if word size is a single byte; 
		//    keep constructor simple 
		boolean ignoreEndianess = searchItemWordSize <= 8;
		List<BpsPattern> endianOutput = new ArrayList<>();
		if (!ignoreEndianess && config.isSearchLE()) {
			for (BpsPattern pattern : originals) {
				if (config.isSearchBE()) {
					endianOutput.add(pattern); // maintain BE arrangement
				}
				endianOutput.add(createLEPattern(pattern));
			}
		}
		else {
			endianOutput = originals;
		}

		// 2. Process pattern splitting if needed
		boolean splitPattern = config.getProgramWordSize() < searchItemWordSize;
		List<BpsPattern> splitOutput = new ArrayList<>();
		if (splitPattern) {
			for (BpsPattern pattern : endianOutput) {
				splitOutput.addAll(createSplitPattern(pattern, config));
			}
		}
		else {
			splitOutput = endianOutput;
		}

		// 3. Process pattern expansion if needed
		List<BpsPattern> finalOutput = new ArrayList<>();
		if (config.isExtendPattern()) {
			for (BpsPattern pattern : splitOutput) {
				finalOutput.addAll(createExtendedPattern(pattern, config));
			}
		}
		else {
			finalOutput = splitOutput;
		}
		return finalOutput;
	}

	/**
	 * Rearrange a big endian pattern to be little endian. This is generally completed prior to
	 * performing any zero-extending or splitting of byte patterns.
	 * 
	 * @param pattern big endian byte pattern
	 * 
	 * @return little endian pattern arrangement
	 */
	private BpsPattern createLEPattern(BpsPattern pattern) {

		BpsTransformation transformation = pattern.getTransformation();
		BpsTransformation leTransformation = transformation.asLittleEndian();

		ByteBuffer leBuff = createLitteEndianBuffer(pattern);
		String name = pattern.getName();
		BpsSearchItem searchItem = pattern.getSearchItem();
		return new BpsPattern(name, leBuff, searchItem, leTransformation);
	}

	/**
	 * Generate LE arrangement of pattern.
	 * 
	 * @param pattern to make LE
	 * 
	 * @return pattern LE byte buffer
	 */
	private ByteBuffer createLitteEndianBuffer(BpsPattern pattern) {
		ByteBuffer originalBuffer = pattern.getBuffer();
		int capacity = originalBuffer.capacity();
		ByteBuffer leBuff = ByteBuffer.allocate(capacity);
		leBuff.order(ByteOrder.LITTLE_ENDIAN);

		BpsSearchItem searchItem = pattern.getSearchItem();
		int wordSize = searchItem.getWordSize();
		switch (wordSize) {
			case 16:
				short asShort = originalBuffer.getShort();
				leBuff.putShort(asShort);
				break;

			case 32:
				int asInt = originalBuffer.getInt();
				leBuff.putInt(asInt);
				break;

			case 64:
				long asLong = originalBuffer.getLong();
				leBuff.putLong(asLong);
				break;
		}
		return leBuff;
	}

	/**
	 * Split a byte pattern to fit within the program's word boundary as indicated in the search
	 * configuration {@link BpsConfig}. More than a single split is possible depending on the word
	 * size of the pattern and the word size boundary of the program.
	 * <P>
	 * All split byte segments are placed in a list and stored as separate, split, patterns as
	 * tracked by each pattern's {@link BpsTransformation}. The searcher will submit searches and
	 * perform follow-on processing to ensure that split patterns are found appropriately adjacent
	 * to each other.
	 * <P>
	 * This transformation is generally performed after little endian rearrangement, if it is
	 * required, and prior to pattern zero-extention, if it is required.
	 * 
	 * @param pattern to be split
	 * @param config search configuration
	 * 
	 * @return split pattern
	 */
	private List<BpsPattern> createSplitPattern(BpsPattern pattern, BpsConfig config) {

		// Pattern's byte buffer has read-only protections
		ByteBuffer originalByteBuffer = pattern.getBuffer();
		byte[] bytes = new byte[originalByteBuffer.remaining()];

		BpsSearchItem searchItem = pattern.getSearchItem();
		int programWordSize = config.getProgramWordSize();
		int numOfSplits = searchItem.getWordSize() / programWordSize;
		int targetByteSize = bytes.length / numOfSplits;
		byte[][] splitBytes = new byte[numOfSplits][targetByteSize];

		List<BpsPattern> splitPatterns = new ArrayList<BpsPattern>();
		for (int i = 0; i < numOfSplits; i++) {
			originalByteBuffer.get(splitBytes[i], 0, targetByteSize);
			BpsTransformation transformation = pattern.getTransformation();
			Endian endianness = transformation.endianness();
			int splitIndex = i + 1;

			// If a pattern needs split, we can confidently assume that it has not been previously
			// zero-extended, so we can safely null out this value in the new record.
			BpsTransformation newTransformation = new BpsTransformation(endianness,
				null, programWordSize, splitIndex, numOfSplits);

			String patternName = pattern.getName();
			ByteBuffer buffer = ByteBuffer.wrap(splitBytes[i]);
			BpsPattern splitPattern =
				new BpsPattern(patternName, buffer, searchItem, newTransformation);

			splitPatterns.add(splitPattern);
		}
		return splitPatterns;
	}

	/**
	 * Zero-extend a byte pattern to fill the program's word size boundary. We perform padding
	 * quantization to accommodate program word sizes which are more than twice the size of the
	 * pattern's word size.
	 * <P>
	 * <i> Quantization Extension Examples: </i>
	 * <table border="1">
	 * <tr>
	 * <th>Pattern Word Size</th>
	 * <th>Program Word Size</th>
	 * <th>Generated Extended Patterns</th>
	 * </tr>
	 * <tr>
	 * <td align=center>16</td>
	 * <td align=center>64</td>
	 * <td align=center>32 and 64</td>
	 * </tr>
	 * <tr>
	 * <td align=center>32</td>
	 * <td align=center>64</td>
	 * <td align=center>64</td>
	 * </tr>
	 * </table>
	 * <P>
	 * This transformation is generally performed after little endian rearrangement, if it is
	 * required, and after pattern splitting, if it is required.
	 * 
	 * @param pattern byte pattern for extension
	 * @param config search configuration
	 * 
	 * @return extended pattern
	 */
	private List<BpsPattern> createExtendedPattern(BpsPattern pattern, BpsConfig config) {

		List<BpsPattern> paddedBytesList = new ArrayList<BpsPattern>();
		BpsSearchItem searchItem = pattern.getSearchItem();
		int searchItemWordSize = searchItem.getWordSize();
		int programWordSize = config.getProgramWordSize();
		List<Integer> padSizes = getPadSizes(searchItemWordSize, programWordSize);

		for (int size : padSizes) {
			BpsPattern extendedPattern = padByteArray(pattern, size);
			paddedBytesList.add(extendedPattern);
		}
		return paddedBytesList;
	}

	/**
	 * If the user requests to extend the data types to fit in the program's word size (and the
	 * search bytes' word size is smaller than the program's), we zero-pad the byte array.
	 * <P>
	 * <B> The endianness of the pattern dictates where the zeros are placed: </B>
	 * <P>
	 * <I> Big endian</I>: zeros are placed on the right of each byte - at the highest address
	 * <P>
	 * <I> Little endian</I>: zeros are placed on the left of each byte - at the lowest address
	 * <p>
	 * 
	 * @param pattern to be extended
	 * @param targetSize word size to extend to
	 * 
	 * @return extended pattern
	 */
	private BpsPattern padByteArray(BpsPattern pattern, int targetSize) {

		// Calculate total bytes needed for the target size
		int byteWordSize = 8;
		int totalBytes = targetSize / byteWordSize;
		ByteBuffer paddedBuffer = ByteBuffer.allocate(totalBytes);

		ByteBuffer storedBuffer = pattern.getBuffer().duplicate();
		byte[] bytes = new byte[storedBuffer.remaining()];
		storedBuffer.get(bytes);

		// Insert zeros and data based on true Endian alignment
		BpsTransformation transformations = pattern.getTransformation();
		Endian endianness = transformations.endianness();
		if (endianness == Endian.LITTLE) {
			// Little Endian: Data goes at the lowest addresses (start of buffer)
			paddedBuffer.put(bytes);
			while (paddedBuffer.hasRemaining()) {
				paddedBuffer.put((byte) 0x00);
			}
		}
		else {
			// Big Endian: Data goes at the highest addresses (end of buffer)
			int numZeros = totalBytes - bytes.length;
			for (int p = 0; p < numZeros; p++) {
				paddedBuffer.put((byte) 0x00);
			}
			paddedBuffer.put(bytes);
		}

		// Expanded patterns will not previously have been split, so we can confidently null those
		// details related to splitting out
		BpsTransformation newTransformation = new BpsTransformation(endianness, targetSize,
			null, null, null);

		String patternName = pattern.getName();
		BpsSearchItem parentSearchItem = pattern.getSearchItem();
		return new BpsPattern(patternName, paddedBuffer, parentSearchItem, newTransformation);
	}

	/**
	 * Helper method for determining the collection of word sizes to zero-pad a byte array to.
	 * <P>
	 * This could be 1 or more size values depending on the comparison between the pattern's word
	 * size and the program's word size.
	 * <P>
	 * <B>Quantization Example:</B> if the pattern word size is 16bit and the program's word size is
	 * 64, we should zero-pad to 32bit and 64bit - returning both of these numbers as pad sizes to
	 * cycle through later.
	 * <p>
	 * NOTE: At this point, we know that zero-padding needs to take place based on previous checks.
	 * We are safely assuming that the word size of the search byte array is at least 16bit because
	 * of previous filtering.
	 * <p>
	 * 
	 * @param patternWordSize bit length of the pattern to extend
	 * @param progWordSize bit length of the program's word size boundary
	 * 
	 * @return list of word sizes to extend to
	 */
	private List<Integer> getPadSizes(int patternWordSize, int progWordSize) {
		List<Integer> padSizes = new ArrayList<Integer>();

		switch (progWordSize) {
			case 32:
				padSizes.add(32);
				break;
			case 64:
				// Quantization: if the byte array's word size is 16, we pad to 32 as well as 64.
				if (patternWordSize == 16) {
					padSizes.add(32);
				}
				padSizes.add(64);
		}
		return padSizes;
	}
}
