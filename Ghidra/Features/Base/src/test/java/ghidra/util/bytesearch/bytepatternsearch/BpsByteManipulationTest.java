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

import static org.junit.Assert.*;

import java.io.File;
import java.nio.ByteBuffer;
import java.util.*;

import org.junit.Test;
import org.xml.sax.SAXException;

import ghidra.program.model.lang.Endian;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class BpsByteManipulationTest {

	BpsTransformationEngine patternTransformer = new BpsTransformationEngine();

	/**
	 * Helper method to produce a list of {@link BpsPattern} objects for testing.
	 * 
	 * @return patterns generated from provided byte string.
	 */
	private List<BpsPattern> createPatterns(String bytes, int wordSize) {
		byte[] rawBytes = HexFormat.of().parseHex(bytes);
		ByteBuffer buffer = ByteBuffer.wrap(rawBytes);

		BpsPattern searchBytes = new BpsPattern("Bytes", buffer,
			new BpsSearchItem("ParentSearchItem", "TestFile_TestItem_0", wordSize,
				BpsSearchType.TABLE_SEARCH),
			BpsTransformation.empty());
		return List.of(searchBytes);
	}

	/**
	 * Helper method to generate wrappers around the provided search item so that
	 * .prepareSearchItemBytes() can be called.
	 * 
	 * @param searchItem BpsSearchItem
	 * 
	 * @return list of searches
	 */
	private List<BpsSearch> makeSearchCollection(BpsSearchItem searchItem) {
		List<BpsSearch> searchCollection = new ArrayList<BpsSearch>();
		List<BpsSearchItem> items = new ArrayList<BpsSearchItem>();
		items.add(searchItem);

		BpsSearch searchItems = new BpsSearch("SearchItems1", "key", items);
		searchCollection.add(searchItems);
		return searchCollection;
	}

	/**
	 * Helper for search context preferences - big endian, no extension
	 * 
	 * @param programWordSize word size of program
	 * 
	 * @return search config
	 */
	private BpsConfig beSearch(int programWordSize, boolean isExtend) {
		return new BpsConfigBuilder(programWordSize)
				.setPerformExtension(isExtend)
				.setBigEndianSearch(true)
				.setLittleEndianSearch(false)
				.build();
	}

	/**
	 * Helper for search context preferences - little endian, no extension
	 * 
	 * @param programWordSize word size of program
	 * 
	 * @return search config
	 */
	private BpsConfig leSearch(int programWordSize, boolean isExtend) {
		return new BpsConfigBuilder(programWordSize)
				.setPerformExtension(isExtend)
				.setBigEndianSearch(false)
				.setLittleEndianSearch(true)
				.build();
	}

	/**
	 * Helper for search context preferences - big & little endian, no extension
	 * 
	 * @param programWordSize word size of program
	 * 
	 * @return search config
	 */
	private BpsConfig beLeSearch(int programWordSize, boolean isExtend) {
		return new BpsConfigBuilder(programWordSize)
				.setPerformExtension(isExtend)
				.setBigEndianSearch(true)
				.setLittleEndianSearch(true)
				.build();
	}

	@Test
	public void testNoTransformationsNeeded() {
		// assume bytes have already been parsed
		String bytes = "0123";
		List<BpsPattern> bytePatterns = createPatterns(bytes, 32);

		BpsSearchItem searchItem =
			new BpsSearchItem("Test", "key1", 32, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);

		List<BpsSearch> search = makeSearchCollection(searchItem);

		// Prepare byte string based on search preferences indicated in the configObject
		// these would be determined at runtime
		BpsConfig config = beSearch(32, false);
		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		assertEquals(1, preppedPatterns.size());
	}

	/**
	 * Simple test to reverse big endian bytes parsed from XML file to little endian. Perform word
	 * data type.
	 */
	@Test
	public void testLittleEndianByteArrangmentWord() {

		// assume bytes have already been parsed
		String bytes = "0123";
		List<BpsPattern> bytePatterns = createPatterns(bytes, 16);

		BpsSearchItem searchItem =
			new BpsSearchItem("Test", "key1", 16, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);

		List<BpsSearch> search = makeSearchCollection(searchItem);

		// Prepare byte string based on search preferences indicated in the configObject
		// these would be determined at runtime
		BpsConfig config = leSearch(32, false);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		String littleEndian = "2301";

		ByteBuffer byteBuffer = preppedPatterns.get(0).getBuffer();
		byte[] byteArray = new byte[byteBuffer.remaining()];
		byteBuffer.get(byteArray);

		assertEquals("Search bytes need reversed to match little endian machine", littleEndian,
			HexFormat.of().formatHex(byteArray));
	}

	/**
	 * Simple test to reverse big endian bytes parsed from XML file to little endian. Perform DWord
	 * data type.
	 */
	@Test
	public void testLittletEndianByteArrangementDWord() {

		List<BpsPattern> bytePatterns = createPatterns("01234567", 32);
		BpsSearchItem searchItem =
			new BpsSearchItem("Test Pattern", "key", 32, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);
		List<BpsSearch> search = makeSearchCollection(searchItem);

		// these would be determined at runtime
		BpsConfig config = leSearch(32, false);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		assertEquals(1, preppedPatterns.size());

		String littleEndian = "67452301";

		ByteBuffer storedBytes = preppedPatterns.get(0).getBuffer();
		byte[] byteArray = new byte[storedBytes.remaining()];
		storedBytes.get(byteArray);

		assertEquals("Search bytes need reversed to match little endian machine", littleEndian,
			HexFormat.of().formatHex(byteArray));
	}

	/**
	 * Simple test to reverse big endian bytes parsed from XML file to little endian. Perform QWord
	 * data type.
	 */
	@Test
	public void testLittleEndianByteArrangementQWord() {
		// QWord
		String bytes = "0123456789abcdef";
		List<BpsPattern> bytePatterns = createPatterns(bytes, 64);
		BpsSearchItem searchItem =
			new BpsSearchItem("Test", "key", 64, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);
		List<BpsSearch> search = makeSearchCollection(searchItem);

		// these would be determined at runtime
		BpsConfig config = leSearch(64, false);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		String littleEndian = "efcdab8967452301";
		ByteBuffer storedBytes = preppedPatterns.get(0).getBuffer();
		byte[] byteArray = new byte[storedBytes.remaining()];
		storedBytes.get(byteArray);

		assertEquals("Search bytes need reversed to match little endian machine", littleEndian,
			HexFormat.of().formatHex(byteArray));
	}

	/**
	 * The user has selected "little endian" in the GUI as an alternative search arrangement to the
	 * default. In this case, the original big endian arrangement should be kept with an additional
	 * arrangement for little endian made.
	 */
	@Test
	public void testUserConfigLittleAndBigEndian() {

		// assume bytes have already been parsed
		List<BpsPattern> bytePatterns = createPatterns("01234567", 32);

		BpsSearchItem searchItem =
			new BpsSearchItem("Test", "key", 32, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);
		List<BpsSearch> search = makeSearchCollection(searchItem);

		BpsConfig config = beLeSearch(32, false);

		// prepare byte string based on search preferences indicated in the configObject
		List<BpsPattern> preppedPatterns = patternTransformer.createPatterns(search, config);

		// since the user selected to search LE, assume BE should also be searched unless
		// ignoreDefaultEndianness was checked
		assertEquals(2, preppedPatterns.size());

		String littleEndian = "67452301";
		ByteBuffer storedBytes = preppedPatterns.get(0).getBuffer();
		byte[] defaultSearchBytes = new byte[storedBytes.remaining()];
		storedBytes.get(defaultSearchBytes);

		storedBytes = preppedPatterns.get(1).getBuffer();
		byte[] littleEndianBytes = new byte[storedBytes.remaining()];
		storedBytes.get(littleEndianBytes);

		assertEquals("BE search needs kept", "01234567",
			HexFormat.of().formatHex(defaultSearchBytes));
		assertEquals("Search bytes need reversed to match little endian machine", littleEndian,
			HexFormat.of().formatHex(littleEndianBytes));
	}

	/**
	 * Simple test to ensure correct splitting of bytes between byte arrays when the DataType size
	 * is larger than the program size.
	 * 
	 * If the original byte array needs to be split based on program size, the splits are placed in
	 * the re-arranged byte arrays and the original byte array should not be cleared out.
	 */
	@Test
	public void testBigEndianByteArraySingleSplit() {

		// assume bytes have already been parsed
		String bytes = "0123456789abcdef";
		List<BpsPattern> bytePatterns = createPatterns(bytes, 64);

		// DataType=QWord, SearchType="Constant", parsed bytes
		BpsSearchItem searchItem = new BpsSearchItem("", "key", 64, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);

		List<BpsSearch> search = makeSearchCollection(searchItem);

		// these would be determined at runtime
		BpsConfig config = beSearch(32, false);

		// prepare byte patterns based on search preferences indicated in the configObject
		List<BpsPattern> preppedPatterns = patternTransformer.createPatterns(search, config);

		String firstSplit = "01234567";
		String secondSplit = "89abcdef";
		// split byte arrays

		BpsPattern bpsPatternFirstSplit = preppedPatterns.get(0);
		ByteBuffer storedBuffer = bpsPatternFirstSplit.getBuffer();
		byte[] firstSplitBytes = new byte[storedBuffer.remaining()];
		storedBuffer.get(firstSplitBytes);

		BpsPattern bpsPatternSecondSplit = preppedPatterns.get(1);
		storedBuffer = bpsPatternSecondSplit.getBuffer();
		byte[] secondSplitBytes = new byte[storedBuffer.remaining()];
		storedBuffer.get(secondSplitBytes);

		// evaluate the bytes for each split
		assertEquals("Original pattern split twice", 2, preppedPatterns.size());
		assertEquals("QWord needs to split to accommodate 32bit prog size", firstSplit,
			HexFormat.of().formatHex(firstSplitBytes));
		assertEquals("QWord needs split to accommodate 32bit prog size", secondSplit,
			HexFormat.of().formatHex(secondSplitBytes));

		// evaluate the description for each split		
		BpsTransformation firstSplitTransformation = bpsPatternFirstSplit.getTransformation();
		Integer firstSplitPartIndex = firstSplitTransformation.splitPartIndex();
		assertEquals("This is the first split", 1, firstSplitPartIndex.intValue());
		assertEquals("Description needs fixed",
			"[Pattern Name: ParentSearchItem | Word Size: 64] -> Pattern: 01 23 45 67 | Form: " +
				"[Endian: Big -> Split to 32 Word Size | Chunk 1 of 2]",
			bpsPatternFirstSplit.getDescription());

		BpsTransformation secondSplitTransformation = bpsPatternSecondSplit.getTransformation();
		Integer secondSplitPartIndex = secondSplitTransformation.splitPartIndex();
		assertEquals("This is the second split", 2, secondSplitPartIndex.intValue());
		assertEquals("Description needs fixed",
			"[Pattern Name: ParentSearchItem | Word Size: 64] -> Pattern: 89 AB CD EF | Form: " +
				"[Endian: Big -> Split to 32 Word Size | Chunk 2 of 2]",
			bpsPatternSecondSplit.getDescription());
	}

	/**
	 * Make sure splitting is happening generically, adjust search data type to DWord and program
	 * size to 16.
	 */
	@Test
	public void testBigEndianSplitDWord() {

		List<BpsPattern> bytePatterns = createPatterns("01234567", 32);

		BpsSearchItem searchItem =
			new BpsSearchItem("Search 1", "key", 32, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);

		List<BpsSearch> search = makeSearchCollection(searchItem);

		BpsConfig config = beSearch(16, false);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		String firstSplit = "0123";
		String secondSplit = "4567";

		ByteBuffer storedBuffer = preppedPatterns.get(0).getBuffer();
		byte[] storedBytes1 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes1);

		storedBuffer = preppedPatterns.get(1).getBuffer();
		byte[] storedBytes2 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes2);

		assertEquals("DWord needs split to accommodate 16bit prog size", firstSplit,
			HexFormat.of().formatHex(storedBytes1));

		assertEquals("DWord needs split to accommodate 16bit prog size", secondSplit,
			HexFormat.of().formatHex(storedBytes2));
	}

	/**
	 * Ensure correct splitting of bytes between byte arrays when the DataType size is larger than
	 * the program size -- in this case, multiple splits of the byte array will be needed.
	 */
	@Test
	public void testBigEndianMultiSplit() {

		// assume bytes have already been parsed, QWord
		String bytes = "0123456789abcdef";
		List<BpsPattern> bytePatterns = createPatterns(bytes, 64);

		BpsSearchItem searchItem =
			new BpsSearchItem("Test", "key", 64, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);

		List<BpsSearch> search = makeSearchCollection(searchItem);

		// these would be determined at runtime
		BpsConfig config = beSearch(16, false); // this will require 4 splits of the byte array

		// prepare byte string based on search preferences indicated in the configObject
		List<BpsPattern> preppedPatterns = patternTransformer.createPatterns(search, config);

		ByteBuffer storedBuffer = preppedPatterns.get(0).getBuffer();
		byte[] storedBytes1 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes1);

		assertEquals("There should be 4 splits, do not keep the original byte array", 4,
			preppedPatterns.size());

		String firstSplit = "0123";
		String secondSplit = "4567";
		String thirdSplit = "89ab";
		String fourthSplit = "cdef";

		storedBuffer = preppedPatterns.get(0).getBuffer();
		storedBytes1 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes1);

		storedBuffer = preppedPatterns.get(1).getBuffer();
		byte[] storedBytes2 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes2);

		storedBuffer = preppedPatterns.get(2).getBuffer();
		byte[] storedBytes3 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes3);

		storedBuffer = preppedPatterns.get(3).getBuffer();
		byte[] storedBytes4 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes4);

		assertEquals("QWord needs split to accommodate 16bit prog size", firstSplit,
			HexFormat.of().formatHex(storedBytes1));
		assertEquals("QWord needs split to accommodate 16bit prog size", secondSplit,
			HexFormat.of().formatHex(storedBytes2));
		assertEquals("QWord needs split to accommodate 16bit prog size", thirdSplit,
			HexFormat.of().formatHex(storedBytes3));
		assertEquals("QWord needs split to accommodate 16bit prog size", fourthSplit,
			HexFormat.of().formatHex(storedBytes4));
	}

	/**
	 * Simple test to ensure correct splitting of LE bytes when the DataType size is larger than the
	 * program size.
	 */
	@Test
	public void testLittleEndianByteArraySingleSplit() {

		// assume bytes have already been parsed
		String bytes = "0123456789abcdef";
		List<BpsPattern> bytePatterns = createPatterns(bytes, 64);

		// DataType=QWord, SearchType="Constant", parsed bytes
		BpsSearchItem searchItem =
			new BpsSearchItem("", "key", 64, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);

		List<BpsSearch> search = makeSearchCollection(searchItem);

		// these would be determined at runtime
		BpsConfig config = leSearch(32, false);

		// prepare byte patterns based on search preferences indicated in the configObject
		List<BpsPattern> preppedPatterns = patternTransformer.createPatterns(search, config);

		String firstSplit = "efcdab89";
		String secondSplit = "67452301";

		BpsPattern firstSplitPattern = preppedPatterns.get(0);
		ByteBuffer storedBuffer = firstSplitPattern.getBuffer();
		byte[] storedBytes1 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes1);

		BpsPattern secondSplitPattern = preppedPatterns.get(1);
		storedBuffer = secondSplitPattern.getBuffer();
		byte[] storedBytes2 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes2);

		assertEquals("Pattern is split in half", 2, preppedPatterns.size());

		// evaluate bytes are LE for each split
		assertEquals("QWord needs reversed & split to accommodate 32bit prog size", firstSplit,
			HexFormat.of().formatHex(storedBytes1));
		assertEquals("QWord needs reversed & to accommodate 32bit prog size", secondSplit,
			HexFormat.of().formatHex(storedBytes2));

		// evaluate description of the transformation
		BpsTransformation firstSplitTransformations = firstSplitPattern.getTransformation();
		BpsTransformation secondSplitTransformations = secondSplitPattern.getTransformation();

		assertEquals("This is the first split", 1,
			firstSplitTransformations.splitPartIndex().intValue());
		assertEquals("Description needs fixed",
			"[Pattern Name: ParentSearchItem | Word Size: 64] -> Pattern: EF CD AB 89 | Form: " +
				"[Endian: Little -> Split to 32 Word Size | Chunk 1 of 2]",
			firstSplitPattern.getDescription());

		assertEquals("This is the second split", 2,
			secondSplitTransformations.splitPartIndex().intValue());
		assertEquals("Description needs fixed",
			"[Pattern Name: ParentSearchItem | Word Size: 64] -> Pattern: 67 45 23 01 | Form: " +
				"[Endian: Little -> Split to 32 Word Size | Chunk 2 of 2]",
			secondSplitPattern.getDescription());
	}

	/**
	 * Make sure LE splitting is happening generically, adjust search data type to DWord and program
	 * size to 16.
	 */
	@Test
	public void testLittleEndianSplitDWord() {

		List<BpsPattern> bytePatterns = createPatterns("01234567", 32);

		BpsSearchItem searchItem =
			new BpsSearchItem("Search 1", "key", 32, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);

		List<BpsSearch> search = makeSearchCollection(searchItem);

		BpsConfig config = leSearch(16, false);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		String firstSplit = "6745";
		String secondSplit = "2301";

		ByteBuffer storedBuffer = preppedPatterns.get(0).getBuffer();
		byte[] storedBytes1 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes1);

		storedBuffer = preppedPatterns.get(1).getBuffer();
		byte[] storedBytes2 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes2);

		assertEquals("LE DWord needs split to accommodate 16bit prog size", firstSplit,
			HexFormat.of().formatHex(storedBytes1));

		assertEquals("LE DWord needs split to accommodate 16bit prog size", secondSplit,
			HexFormat.of().formatHex(storedBytes2));
	}

	/**
	 * Ensure correct splitting of LE bytes between byte arrays when the DataType size is larger
	 * than the program size -- in this case, multiple splits of the byte array will be needed.
	 * 
	 */
	@Test
	public void testLEMultiSplit() {

		// assume bytes have already been parsed, QWord
		String bytes = "0123456789abcdef";
		List<BpsPattern> bytePatterns = createPatterns(bytes, 64);

		BpsSearchItem searchItem =
			new BpsSearchItem("Test", "key", 64, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);

		List<BpsSearch> search = makeSearchCollection(searchItem);

		// these would be determined at runtime
		BpsConfig config = leSearch(16, false); // this will require 4 splits of the byte array

		// prepare byte string based on search preferences indicated in the configObject
		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		ByteBuffer storedBuffer = preppedPatterns.get(0).getBuffer();
		byte[] storedBytes1 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes1);

		assertEquals("There should be 4 splits, do not keep the original byte array", 4,
			preppedPatterns.size());

		String firstSplit = "efcd";
		String secondSplit = "ab89";
		String thirdSplit = "6745";
		String fourthSplit = "2301";

		storedBuffer = preppedPatterns.get(0).getBuffer();
		storedBytes1 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes1);

		storedBuffer = preppedPatterns.get(1).getBuffer();
		byte[] storedBytes2 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes2);

		storedBuffer = preppedPatterns.get(2).getBuffer();
		byte[] storedBytes3 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes3);

		storedBuffer = preppedPatterns.get(3).getBuffer();
		byte[] storedBytes4 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes4);

		assertEquals("QWord needs LE & split to accommodate 16bit prog size", firstSplit,
			HexFormat.of().formatHex(storedBytes1));
		assertEquals("QWord needs LE & split to accommodate 16bit prog size", secondSplit,
			HexFormat.of().formatHex(storedBytes2));
		assertEquals("QWord needs LE & split to accommodate 16bit prog size", thirdSplit,
			HexFormat.of().formatHex(storedBytes3));
		assertEquals("QWord needs LE & split to accommodate 16bit prog size", fourthSplit,
			HexFormat.of().formatHex(storedBytes4));
	}

	/**
	 * In the case where the data type needs split because of the program size and we are searching
	 * both BE and LE - perform the little endian arrangement first and then split; keep BE
	 * arrangement.
	 */
	@Test
	public void testLeAndBeNeedSplit() {

		// assume bytes have already been parsed
		String bytes = "0123456789abcdef";
		List<BpsPattern> bytePatterns = createPatterns(bytes, 64);

		// DataType=QWord, SearchType="Constant", no additional tags from XML, parsed bytes
		BpsSearchItem searchItem =
			new BpsSearchItem("Test", "key", 64, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);
		List<BpsSearch> search = makeSearchCollection(searchItem);

		// these would be determined at runtime
		BpsConfig config = beLeSearch(32, false);

		// prepare byte string based on search preferences indicated in the configObject
		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		// both BE and LE patterns are split into 2
		assertEquals("There should be 4 total byte arrays to search for", 4,
			preppedPatterns.size());

		String firstSplitLE = "efcdab89";
		String secondSplitLE = "67452301";

		ByteBuffer storedBuffer = preppedPatterns.get(2).getBuffer();
		byte[] storedLeBytes1 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedLeBytes1);

		storedBuffer = preppedPatterns.get(3).getBuffer();
		byte[] storedBeBytes2 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBeBytes2);

		assertEquals("QWord needs reversed & split to accommodate 32bit prog size", firstSplitLE,
			HexFormat.of().formatHex(storedLeBytes1));

		assertEquals("QWord needs reversed & split to accommodate 32bit prog size", secondSplitLE,
			HexFormat.of().formatHex(storedBeBytes2));
	}

	/**
	 * Test LE BE simultaneous multi split
	 */
	@Test
	public void testBeLeMultiSplit() {
		// assume bytes have already been parsed, QWord
		String bytes = "0123456789abcdef";
		List<BpsPattern> bytePatterns = createPatterns(bytes, 64);

		BpsSearchItem searchItem =
			new BpsSearchItem("Test", "key", 64, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);

		List<BpsSearch> search = makeSearchCollection(searchItem);

		// these would be determined at runtime
		BpsConfig config = beLeSearch(16, false); // this will require 4 splits of both byte arrays

		// prepare byte string based on search preferences indicated in the configObject
		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		assertEquals("There should be 8 splits, do not keep the original byte array", 8,
			preppedPatterns.size());

		String firstSplitBe = "0123";
		String secondSplitBe = "4567";
		String thirdSplitBe = "89ab";
		String fourthSplitBe = "cdef";

		ByteBuffer storedBuffer = preppedPatterns.get(0).getBuffer();
		byte[] storedBytes1 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes1);

		storedBuffer = preppedPatterns.get(0).getBuffer();
		storedBytes1 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes1);

		storedBuffer = preppedPatterns.get(1).getBuffer();
		byte[] storedBytes2 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes2);

		storedBuffer = preppedPatterns.get(2).getBuffer();
		byte[] storedBytes3 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes3);

		storedBuffer = preppedPatterns.get(3).getBuffer();
		byte[] storedBytes4 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes4);

		assertEquals("QWord needs split to accommodate 16bit prog size", firstSplitBe,
			HexFormat.of().formatHex(storedBytes1));
		assertEquals("QWord needs split to accommodate 16bit prog size", secondSplitBe,
			HexFormat.of().formatHex(storedBytes2));
		assertEquals("QWord needs split to accommodate 16bit prog size", thirdSplitBe,
			HexFormat.of().formatHex(storedBytes3));
		assertEquals("QWord needs split to accommodate 16bit prog size", fourthSplitBe,
			HexFormat.of().formatHex(storedBytes4));

		String firstSplitLe = "efcd";
		String secondSplitLe = "ab89";
		String thirdSplitLe = "6745";
		String fourthSplitLe = "2301";

		storedBuffer = preppedPatterns.get(4).getBuffer();
		storedBytes1 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes1);

		storedBuffer = preppedPatterns.get(5).getBuffer();
		storedBytes2 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes2);

		storedBuffer = preppedPatterns.get(6).getBuffer();
		storedBytes3 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes3);

		storedBuffer = preppedPatterns.get(7).getBuffer();
		storedBytes4 = new byte[storedBuffer.remaining()];
		storedBuffer.get(storedBytes4);

		assertEquals("QWord needs LE & split to accommodate 16bit prog size", firstSplitLe,
			HexFormat.of().formatHex(storedBytes1));
		assertEquals("QWord needs LE & split to accommodate 16bit prog size", secondSplitLe,
			HexFormat.of().formatHex(storedBytes2));
		assertEquals("QWord needs LE & split to accommodate 16bit prog size", thirdSplitLe,
			HexFormat.of().formatHex(storedBytes3));
		assertEquals("QWord needs LE & split to accommodate 16bit prog size", fourthSplitLe,
			HexFormat.of().formatHex(storedBytes4));

	}

	/**
	 * Simple test to verify that the description string is correctly concatenated when multiple
	 * manipulations have been performed.
	 */
	@Test
	public void testMultiManipulationAndMultiSplitDescriptionString() {
		List<BpsPattern> bytePatterns = createPatterns("01234567", 32);
		BpsSearchItem searchItem =
			new BpsSearchItem("Test pattern", "key", 32, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);
		List<BpsSearch> search = makeSearchCollection(searchItem);

		BpsConfig config = leSearch(16, false);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		// evaluate descriptions at the pattern level and transformation level
		BpsPattern firstSplitPattern = preppedPatterns.get(0);
		assertEquals("Pattern description string needs fixed",
			"[Pattern Name: ParentSearchItem | Word Size: 32] -> Pattern: 67 45 | Form: " +
				"[Endian: Little -> Split to 16 Word Size | Chunk 1 of 2]",
			firstSplitPattern.getDescription());
		BpsTransformation firstSplitTransformation = firstSplitPattern.getTransformation();
		assertEquals("Transformation Description string needs fixed",
			"Endian: Little -> Split to 16 Word Size | Chunk 1 of 2",
			firstSplitTransformation.getDescription());

		BpsPattern secondSplitPattern = preppedPatterns.get(1);
		assertEquals("Pattern description string needs fixed",
			"[Pattern Name: ParentSearchItem | Word Size: 32] -> Pattern: 23 01 | Form: " +
				"[Endian: Little -> Split to 16 Word Size | Chunk 2 of 2]",
			secondSplitPattern.getDescription());
		BpsTransformation secondSplitTransformation = secondSplitPattern.getTransformation();
		assertEquals("Transformation Description string needs fixed",
			"Endian: Little -> Split to 16 Word Size | Chunk 2 of 2",
			secondSplitTransformation.getDescription());

	}

	/**
	 * Simple test to zero-pad a 16bit word size to 32bit program size, BE.
	 */
	@Test
	public void testSimpleBeBytePadding() {
		List<BpsPattern> bytePatterns = createPatterns("1122", 16);
		BpsSearchItem searchItem =
			new BpsSearchItem("Test pattern", "key", 16, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);
		List<BpsSearch> search = makeSearchCollection(searchItem);

		BpsConfig config = beSearch(32, true);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		String bytes = "00001122";
		ByteBuffer storedBuffer = preppedPatterns.get(0).getBuffer();
		byte[] paddedBytes = new byte[storedBuffer.remaining()];
		storedBuffer.get(paddedBytes);

		assertEquals("BE padding is to the right of the byte", bytes,
			HexFormat.of().formatHex(paddedBytes));

		BpsTransformation patternTransformation = preppedPatterns.get(0).getTransformation();
		assertEquals("Transformation record must show padding size",
			"Endian: Big -> Padded to 32", patternTransformation.getDescription());
	}

	/**
	 * Simple test to zero-pad a 16bit word size to 32bit program size, LE.
	 */
	@Test
	public void testSimpleLeBytePadding() {
		List<BpsPattern> bytePatterns = createPatterns("1122", 16);
		BpsSearchItem searchItem =
			new BpsSearchItem("Test pattern", "key", 16, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);
		List<BpsSearch> search = makeSearchCollection(searchItem);

		BpsConfig config = leSearch(32, true);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		String bytes = "22110000";

		ByteBuffer storedBuffer = preppedPatterns.get(0).getBuffer();
		byte[] paddedBytes = new byte[storedBuffer.remaining()];
		storedBuffer.get(paddedBytes);

		assertEquals("LE padding is to the right of the byte", bytes,
			HexFormat.of().formatHex(paddedBytes));

		assertEquals("Transformation record must show LE arrangement and padding size",
			"Endian: Little -> Padded to 32",
			preppedPatterns.get(0).getTransformation().getDescription());
	}

	/**
	 * Zero-pad a 16bit word boundary using size quantization for 32 and 64bit word sizes to fit a
	 * 64bit program word boundary, BE.
	 */
	@Test
	public void testPad16to64WordSize() {
		List<BpsPattern> bytePatterns = createPatterns("1122", 16);
		BpsSearchItem searchItem =
			new BpsSearchItem("Test pattern", "key", 16, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);

		List<BpsSearch> search = makeSearchCollection(searchItem);

		BpsConfig config = beSearch(64, true);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		// when padding, we do not search using the original word boundary
		assertEquals("2 new padded byte arrays should have been generated: 32 & 64", 2,
			preppedPatterns.size());

		String bytes32 = "00001122";
		ByteBuffer storedBuffer = preppedPatterns.get(0).getBuffer();
		byte[] padded32Bytes = new byte[storedBuffer.remaining()];
		storedBuffer.get(padded32Bytes);

		BpsTransformation patternTransformation32 = preppedPatterns.get(0).getTransformation();
		assertEquals("32bit BE padding is to the left of the byte", bytes32,
			HexFormat.of().formatHex(padded32Bytes));
		assertEquals("Transformation string must reflect pad 32 size", 32,
			patternTransformation32.extensionSize().intValue());

		String bytes64 = "0000000000001122";
		storedBuffer = preppedPatterns.get(1).getBuffer();
		byte[] padded64Bytes = new byte[storedBuffer.remaining()];
		storedBuffer.get(padded64Bytes);

		BpsTransformation patternTransformation64 = preppedPatterns.get(1).getTransformation();
		assertEquals("64bit BE padding is to the left of the byte", bytes64,
			HexFormat.of().formatHex(padded64Bytes));
		assertEquals("Transformation string must reflect pad 64 size", 64,
			patternTransformation64.extensionSize().intValue());
	}

	/**
	 * Zero-pad a 16bit word boundary using size quantization for 32 and 64bit word sizes to fit a
	 * 64bit program word boundary, LE.
	 */
	@Test
	public void testPad16to64WordSizeLE() {
		List<BpsPattern> bytePatterns = createPatterns("1122", 16);
		BpsSearchItem searchItem =
			new BpsSearchItem("Test pattern", "key", 16, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);

		List<BpsSearch> search = makeSearchCollection(searchItem);

		BpsConfig config = leSearch(64, true);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		assertEquals(
			"2 byte arrays should have been generated: LE-32pad, LE-64pad", 2,
			preppedPatterns.size());

		String bytes32 = "22110000";
		BpsPattern pattern32 = preppedPatterns.get(0);
		ByteBuffer storedBuffer = pattern32.getBuffer();
		byte[] padded32Bytes = new byte[storedBuffer.remaining()];
		storedBuffer.get(padded32Bytes);

		BpsTransformation patternTransformation32 = pattern32.getTransformation();
		assertEquals("32bit LE padding is to the left of the byte", bytes32,
			HexFormat.of().formatHex(padded32Bytes));
		assertEquals("Transformation string must reflect pad 32 size", 32,
			patternTransformation32.extensionSize().intValue());
		assertEquals("Transformation string must reflect LE", Endian.LITTLE,
			patternTransformation32.endianness());

		String bytes64 = "2211000000000000";
		BpsPattern pattern64 = preppedPatterns.get(1);
		storedBuffer = pattern64.getBuffer();
		byte[] padded64Bytes = new byte[storedBuffer.remaining()];
		storedBuffer.get(padded64Bytes);
		BpsTransformation patternTransformation64 = pattern64.getTransformation();
		assertEquals("64bit LE padding is to the left of the byte", bytes64,
			HexFormat.of().formatHex(padded64Bytes));
		assertEquals("Transformation string must reflect pad 64 size", 64,
			patternTransformation64.extensionSize().intValue());
		assertEquals("Transformation string must reflect LE", Endian.LITTLE,
			patternTransformation64.endianness());
	}

	/**
	 * If the user wishes to search both BE and LE and also wants to extend the data types, need to
	 * make sure that 2 new rearranged arrays are generated - both zero-padded, one BE one LE.
	 */
	@Test
	public void testPadBEandLE() {
		List<BpsPattern> bytePatterns = createPatterns("1122", 16);
		BpsSearchItem searchItem =
			new BpsSearchItem("Test pattern", "key", 16, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);

		List<BpsSearch> search = makeSearchCollection(searchItem);
		BpsConfig config = beLeSearch(32, true);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		assertEquals("2 byte arrays should have been generated", 2, preppedPatterns.size());

		String bytesBeExtended = "00001122";
		String bytesLeExtended = "22110000";

		ByteBuffer storedBuffer = preppedPatterns.get(0).getBuffer();
		byte[] paddedBEBytes = new byte[storedBuffer.remaining()];
		storedBuffer.get(paddedBEBytes);

		storedBuffer = preppedPatterns.get(1).getBuffer();
		byte[] paddedLEBytes = new byte[storedBuffer.remaining()];
		storedBuffer.get(paddedLEBytes);

		assertEquals("LE padding is to the right of the byte", bytesLeExtended,
			HexFormat.of().formatHex(paddedLEBytes));
		assertEquals("BE padding is to the left of the byte", bytesBeExtended,
			HexFormat.of().formatHex(paddedBEBytes));
	}

	/**
	 * Pad BE and LE patterns from 16 to 64 word boundary: generate BE and LE patterns with 32 and
	 * 64 word boundaries.
	 */
	@Test
	public void testPadBEandLEQuantization() {
		List<BpsPattern> bytePatterns = createPatterns("1122", 16);
		BpsSearchItem searchItem =
			new BpsSearchItem("Test pattern", "key", 16, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);

		List<BpsSearch> search = makeSearchCollection(searchItem);
		BpsConfig config = beLeSearch(64, true);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		assertEquals("4 byte arrays should have been generated", 4, preppedPatterns.size());

		String bytesBeExtended32 = "00001122";
		String bytesBeExtended64 = "0000000000001122";
		String bytesLeExtended32 = "22110000";
		String bytesLeExtended64 = "2211000000000000";

		ByteBuffer storedBuffer = preppedPatterns.get(0).getBuffer();
		byte[] paddedBEBytes32 = new byte[storedBuffer.remaining()];
		storedBuffer.get(paddedBEBytes32);

		storedBuffer = preppedPatterns.get(1).getBuffer();
		byte[] paddedBEBytes64 = new byte[storedBuffer.remaining()];
		storedBuffer.get(paddedBEBytes64);

		storedBuffer = preppedPatterns.get(2).getBuffer();
		byte[] paddedLEBytes32 = new byte[storedBuffer.remaining()];
		storedBuffer.get(paddedLEBytes32);

		storedBuffer = preppedPatterns.get(3).getBuffer();
		byte[] paddedLEBytes64 = new byte[storedBuffer.remaining()];
		storedBuffer.get(paddedLEBytes64);

		assertEquals("LE padding is to the right of the byte", bytesLeExtended32,
			HexFormat.of().formatHex(paddedLEBytes32));
		assertEquals("BE padding is to the left of the byte", bytesBeExtended32,
			HexFormat.of().formatHex(paddedBEBytes32));
		assertEquals("LE padding is to the right of the byte", bytesLeExtended64,
			HexFormat.of().formatHex(paddedLEBytes64));
		assertEquals("BE padding is to the left of the byte", bytesBeExtended64,
			HexFormat.of().formatHex(paddedBEBytes64));
	}

	@Test
	public void testPaddingQuantizationDescriptionString() {
		List<BpsPattern> bytePatterns = createPatterns("01234567", 16);
		BpsSearchItem searchItem =
			new BpsSearchItem("Test pattern", "key", 16, BpsSearchType.CONSTANT_SEARCH);
		searchItem.setBytePatterns(bytePatterns);
		List<BpsSearch> search = makeSearchCollection(searchItem);

		BpsConfig config = beSearch(64, true);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(search, config);

		BpsPattern pattern32 = preppedPatterns.get(0);
		assertEquals("Transformation string needs fixed",
			"Endian: Big -> Padded to 32", pattern32.getTransformation().getDescription());

		assertEquals("Pattern description string needs fixed",
			"[Pattern Name: ParentSearchItem | Word Size: 16] -> Pattern: 01 23 45 67 | Form: " +
				"[Endian: Big -> Padded to 32]",
			pattern32.getDescription());

		BpsPattern pattern64 = preppedPatterns.get(1);
		assertEquals("Transformation string needs fixed",
			"Endian: Big -> Padded to 64", pattern64.getTransformation().getDescription());

		assertEquals("Pattern description string needs fixed",
			"[Pattern Name: ParentSearchItem | Word Size: 16] -> Pattern: 00 00 00 00 01 23 45 67 | Form: " +
				"[Endian: Big -> Padded to 64]",
			pattern64.getDescription());
	}

	/**
	 * Test the data flow from the parser through pattern preparation.
	 * 
	 * @throws Exception xml parse exception
	 */
	@Test
	public void testParserToLEManipulation() throws Exception {
		String xmlFile =
			"ghidra/util/bytesearch/bytepatternsearch/basic_search_collection.xml";
		File testXmlFile = ResourceManager.getResourceFile(xmlFile);
		List<BpsSearch> searchCollection =
			BpsXmlParser.parseSearchFile(testXmlFile, TaskMonitor.DUMMY);

		assertEquals("Should be 9 family collections of SearchItems", 9, searchCollection.size());
		assertEquals("Original patterns not parsed correctly", 85,
			getPatternCount(searchCollection));

		// these would be determined at runtime
		BpsConfig config = beLeSearch(64, false);

		List<BpsPattern> preparedPatterns =
			patternTransformer.createPatterns(searchCollection, config);

		/*
		 * Pattern count break down:
		 * 85 total patterns parsed x 2 (BE & LE) = 170
		 * 36 patterns are 8 bit (single byte) and will not need transformed to LE: 170-36 = 134
		 * 85 total patterns parsed x 2 (made into LE) - 36 byte word size = 134
		 */
		assertEquals("Additional patterns added from LE manipulation", 134,
			preparedPatterns.size());
	}

	/**
	 * Helper to count the total number of patterns across all searchItems within a search
	 * collection.
	 * 
	 * @param searchCollection list of searches
	 * 
	 * @return total pattern count
	 */
	private int getPatternCount(List<BpsSearch> searchCollection) {

		int totalPatternCount = 0;
		for (BpsSearch searchItems : searchCollection) {
			for (BpsSearchItem item : searchItems.getSearchItems()) {
				totalPatternCount += item.getPatterns().size();
			}
		}
		return totalPatternCount;
	}

	/**
	 * Test pattern file with word size byte. Edge case.
	 * 
	 * @throws Exception xml parse exception
	 */
	@Test
	public void testHandleWordSizeByteProperly() throws Exception {
		String xmlFile =
			"ghidra/util/bytesearch/bytepatternsearch/dword_qword_for32bit_pattern.xml";
		File testXmlFile = ResourceManager.getResourceFile(xmlFile);
		List<BpsSearch> searchCollection =
			BpsXmlParser.parseSearchFile(testXmlFile, TaskMonitor.DUMMY);

		assertEquals("Should be 2 family collections of SearchItems", 2, searchCollection.size());
		assertEquals("Original patterns not parsed correctly", 15,
			getPatternCount(searchCollection));

		// these would be determined at runtime
		BpsConfig config = beLeSearch(64, false);

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(searchCollection, config);

		/*
		 * One pattern contains word size of byte (8bit) will not reverse to LE
		 * Original pattern count: 15
		 * Patterns made LE: 14 (1 pattern will not need reversed) 
		 * Total patterns for search: 15+14 = 29
		 */
		assertEquals("Additional patterns added from LE manipulation", 29, preppedPatterns.size());
	}

	/**
	 * {@link BpsSearch} items should be skippable using the generated key at the
	 * {@link BpsSearchItem} level.
	 */
	@Test
	public void testSkipSearchItem() {
		byte[] rawBytes = HexFormat.of().parseHex("0101");
		ByteBuffer buffer = ByteBuffer.wrap(rawBytes);

		byte[] rawBytes2 = HexFormat.of().parseHex("ABCD");
		ByteBuffer buff2 = ByteBuffer.wrap(rawBytes2);

		BpsSearchItem searchItem =
			new BpsSearchItem("SearchItem1", "SearchItemkey0", 16,
				BpsSearchType.CONSTANT_SEARCH);
		BpsPattern pattern =
			new BpsPattern("Bytes", buffer, searchItem, BpsTransformation.empty());

		List<BpsPattern> bytePatterns = new ArrayList<>();
		bytePatterns.add(pattern);
		searchItem.setBytePatterns(bytePatterns);

		BpsSearchItem searchItem2 =
			new BpsSearchItem("SearchItem2", "SearchItemkey1", 16, BpsSearchType.CONSTANT_SEARCH);
		BpsPattern pattern2 =
			new BpsPattern("Bytes", buff2, searchItem2, BpsTransformation.empty());

		List<BpsPattern> bytePatterns2 = new ArrayList<>();
		bytePatterns2.add(pattern2);
		searchItem2.setBytePatterns(bytePatterns2);

		List<BpsSearchItem> searchItems = new ArrayList<>();
		searchItems.add(searchItem);
		searchItems.add(searchItem2);

		BpsSearch search = new BpsSearch("Search1", "Searchkey1", searchItems);

		List<BpsSearch> searchList = new ArrayList<>();
		searchList.add(search);

		BpsConfig config = beSearch(32, false);

		Set<String> skipList = new HashSet<>();
		skipList.add("SearchItemkey0");

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(searchList, skipList, config);
		assertEquals("1 pattern should have been skipped.", 1, preppedPatterns.size());
		assertFalse(preppedPatterns.contains(searchItem.getPatterns().get(0)));
		assertTrue(preppedPatterns.contains(searchItem2.getPatterns().get(0)));
	}

	/**
	 * Whole {@link BpsSearch} are also skippable
	 */
	@Test
	public void testSkipSearch() {
		byte[] rawBytes = HexFormat.of().parseHex("0101");
		ByteBuffer buffer = ByteBuffer.wrap(rawBytes);

		BpsSearchItem searchItem =
			new BpsSearchItem("SearchItem1", "SearchItemkey0", 16,
				BpsSearchType.CONSTANT_SEARCH);
		BpsPattern pattern =
			new BpsPattern("Bytes", buffer, searchItem, BpsTransformation.empty());

		List<BpsPattern> bytePatterns = new ArrayList<>();
		bytePatterns.add(pattern);
		searchItem.setBytePatterns(bytePatterns);

		BpsSearchItem searchItem2 =
			new BpsSearchItem("SearchItem2", "SearchItemkey1", 16, BpsSearchType.CONSTANT_SEARCH);
		searchItem2.setBytePatterns(bytePatterns);

		List<BpsSearchItem> searchItems = new ArrayList<>();
		searchItems.add(searchItem);
		searchItems.add(searchItem2);

		BpsSearch search = new BpsSearch("Search1", "Searchkey1", searchItems);

		List<BpsSearch> searchList = new ArrayList<>();
		searchList.add(search);

		BpsConfig config = beSearch(32, false);

		Set<String> skipList = new HashSet<>();
		skipList.add("Searchkey1");

		List<BpsPattern> preppedPatterns =
			patternTransformer.createPatterns(searchList, skipList, config);
		assertEquals("All patterns should have been skipped.", 0, preppedPatterns.size());
	}

	/**
	 * Ensure generated keys can be used for skipping multiple things (both at the Search and
	 * SearchItem level).
	 * 
	 * @throws SAXException for XML parsing
	 */
	@Test
	public void testMultiSkipFromGeneratedKey() throws SAXException {
		String xmlFile =
			"ghidra/util/bytesearch/bytepatternsearch/basic_search_collection.xml";
		File testXmlFile = ResourceManager.getResourceFile(xmlFile);
		List<BpsSearch> searchCollection =
			BpsXmlParser.parseSearchFile(testXmlFile, TaskMonitor.DUMMY);

		assertEquals("Full pattern count is wrong", 85, getPatternCount(searchCollection));

		// these would be determined at runtime
		BpsConfig config = beSearch(64, false);

		// the GUI will build and maintain this list from the user's interactions
		Set<String> skipList = new HashSet<>();
		skipList.add(searchCollection.get(0).getId()); // skip the first Search all together

		/*
		 * Skip the 2nd SearchItem in the 2nd Search - this contains 4 patterns, starting on line 14
		 * <SearchItem Name="Constant"  WordSize="DWord" SearchType="Table" Submitter="Human" Description="Simple constant search" Reference="Dictionary">
				<Bytes> 67e6096a85ae67bb </Bytes>
				<Bytes> 67e6096a </Bytes>
				<Bytes> 85ae67bb </Bytes>
				<Bytes> 67e6096a85ae67bb </Bytes>
			</SearchItem>
		 */
		skipList.add(searchCollection.get(1).getSearchItems().get(1).getId());

		List<BpsPattern> preparedPatterns =
			patternTransformer.createPatterns(searchCollection, skipList, config);

		/*
		 * We are skipping:
		 * 	- first search (which contains 1 search item): 1 pattern
		 * 	- second searchItem from the second search: 4 patterns
		 * Total skipped patterns = 5
		 * Total search patterns: 85-5 = 80
		 */
		assertEquals(
			"First search and 2nd search item from 2nd search should have been skipped - 5 less " +
				"patterns.",
			80, preparedPatterns.size());
	}
}
