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
import java.util.HexFormat;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import generic.test.AbstractGenericTest;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class BpsParserTest extends AbstractGenericTest {

	private String xmlFile = "ghidra/util/bytesearch/bytepatternsearch/basic_search_collection.xml";
	private File testXmlFile;
	private List<BpsSearch> searchCollection;

	@Before
	public void setUp() throws Exception {
		testXmlFile = ResourceManager.getResourceFile(xmlFile);
		searchCollection = BpsXmlParser.parseSearchFile(testXmlFile, TaskMonitor.DUMMY);
	}

	/**
	 * Simple test for successful loading and parsing of example XML.
	 */
	@Test
	public void testParserLoadXml() {

		BpsSearch search1 = searchCollection.get(0);
		assertEquals("SearchID wasn't generated correctly", "basic_search_collection.xml_Search1_1",
			search1.getId());
		assertEquals("1", search1.getDescription());
		assertEquals("Search1", search1.getSearchName());
		assertEquals("test", search1.getSubmitter());
		assertEquals("Search1", search1.toString());
		assertEquals("Incorrect number of search items parsed for collection", 1,
			search1.getSearchItems().size());

		BpsSearchItem searchItem = search1.getSearchItems().get(0);
		assertEquals("SearchIteam Id wasn't generated correctly",
			"basic_search_collection.xml_Constant 1_0", searchItem.getId());
		assertEquals("Human", searchItem.getSubmitter());
		assertEquals(searchItem.getSearchType(), BpsSearchType.CONSTANT_SEARCH);
		assertEquals("Simple constant search", searchItem.getDescription());
		assertEquals("Word size wasn't parsed correctly", 64, searchItem.getWordSize()); // QWord becomes 64
	}

	/**
	 * Ensure that multiple collections with multiple searchItems are being parsed correctly
	 */
	@Test
	public void testMultiCollectionParse() {
		assertEquals("Incorrect number of search collections parsed", 9,
			searchCollection.size());

		/*
		 	Search Collection 3
		 	
		 		<Search Name="Search3" Description="" Category="A" Type="Strict">
		 			...
		 		</SearchItem>
		 		
		 		// 8 Search items
		 		
		 */

		BpsSearch search3 = searchCollection.get(2);
		assertEquals("Collection 3 should have 8 search items", 8, search3.getSearchItems().size());

		/*
		 	Search Collection 5 
		 	
		 	<Search Name="Search5" Description="1">
				<SearchItem Name="Constant 1" WordSize="byte" SearchType="Table" Submitter="Human" Description="Simple constant search" Reference="Dictionary">
					<Bytes> 67 </Bytes>	
					...
					...
					// 34 Bytes elements
		 */

		BpsSearch search5 = searchCollection.get(4);
		List<BpsSearchItem> searchItems = search5.getSearchItems();
		BpsSearchItem searchItem = searchItems.get(0);
		List<BpsPattern> bytes = searchItem.getPatterns();
		assertEquals("Collection 5 should have 1 search item with 34 byte tags", 34, bytes.size());
	}

	/*
	 * The current legacy object, and XML, follows a construct with multiple tag types. We need to
	 * respect these tag types and store them as an attribute under "TagType" so that they can be
	 * easily retrieved to handle the bytes appropriately. Some tags are expected to occur
	 * in tandem with each other in the same SearchItem.
	 * <P> 
	 * NOTE: future design is to eliminate multiple tag types and assign attributes to byte tags as
	 * the previous test assumes for.
	 */
	@Test
	public void testByteTagsConvertedToAttributesToFitLegacyObject() {

		int fluxCapacitor = 7;
		BpsSearch search = searchCollection.get(fluxCapacitor);
		List<BpsSearchItem> searchItems = search.getSearchItems();
		BpsSearchItem searchItem = searchItems.get(0);
		BpsPattern bytes = searchItem.getPatterns().get(0);
		String tagName = bytes.getName();

		assertEquals("Parser handles tags around byte strings as attributes",
			"Bytes", tagName);
	}

	/**
	 * When each byte string is parsed, it should be stored according to the indicated DataType
	 * attribute on the {@code<SearchItem>} tag.
	 */
	@Test
	public void testVerifyBytesParsedAccordingToXmlDataType() {
		String originalHexString = "67e6096a85ae67bb";

		BpsSearchItem searchItem = searchCollection.get(0).getSearchItems().get(0);
		BpsPattern bytes = searchItem.getPatterns().get(0);

		// QWord
		ByteBuffer byteBuffer = bytes.getBuffer();
		byte[] byteArray = new byte[byteBuffer.remaining()];
		byteBuffer.get(byteArray);
		assertEquals("Parsed bytes do not match original set", originalHexString,
			HexFormat.of().formatHex(byteArray));

		// Word
		int fluxCapacitor = 5;
		searchItem = searchCollection.get(fluxCapacitor).getSearchItems().get(0);
		bytes = searchItem.getPatterns().get(0);
		byteBuffer = bytes.getBuffer();
		byteArray = new byte[byteBuffer.remaining()];
		byteBuffer.get(byteArray);
		assertEquals("Parsed bytes do not match original set", "67e6",
			HexFormat.of().formatHex(byteArray));
	}

	/**
	 * For ease of tracking search item details later, keep a link between the byte pattern and its
	 * parent search item.
	 */
	@Test
	public void testPatternLinkBacktoParentSearchItem() {
		BpsSearchItem parentItem =
			searchCollection.get(0).getSearchItems().get(0);
		BpsPattern childPattern = parentItem.getPatterns().get(0);

		assertEquals("Patterns should link to their parent search item.", parentItem,
			childPattern.getSearchItem());
		assertEquals("Parent item knows the search type",
			childPattern.getSearchItem().getSearchType(), BpsSearchType.CONSTANT_SEARCH);
	}

	/**
	 * Generate search type objects for tracking search-specific information and use later as 
	 * part of search post-processing. 
	 */
	@Test
	public void testSearchTypeObjectGeneration() {
		BpsSearchItem searchItem = searchCollection.get(0).getSearchItems().get(0);
		assertEquals("Wrong (or no) search type object created", searchItem.getSearchType(),
			BpsSearchType.CONSTANT_SEARCH);

		searchItem = searchCollection.get(1).getSearchItems().get(0);
		assertEquals("Wrong (or no) search type object created", searchItem.getSearchType(),
			BpsSearchType.TABLE_SEARCH);
	}

	@Test
	public void testAdditionalAttributesOnSearchandSearchItems() {
		int searchIndex = 2;
		BpsSearch search = searchCollection.get(searchIndex);
		assertEquals("Search3 tag has 2 additional attributes", 2,
			search.getAdditionalAttributes().size());

		BpsSearchItem searchItem = search.getSearchItems().get(0);
		assertEquals("SearchItem has 1 additional attribute (Reference)", 1,
			searchItem.getAdditionalAttributes().size());
	}

	@Test
	public void testParsingErrorHandler() throws SAXException {
		String currXmlFile = "ghidra/util/bytesearch/bytepatternsearch/parse_errors.xml";
		File currTestXmlFile = ResourceManager.getResourceFile(currXmlFile);
		String message = "";
		int errorCount = 0;
		List<SAXParseException> errors = null;
		try {
			searchCollection = BpsXmlParser.parseSearchFile(currTestXmlFile, TaskMonitor.DUMMY);
			fail("Should have thrown a SAXException but did not");
		}
		catch (BpsXmlValidationException e) {
			message = e.getMessage();
			errorCount = e.getErrorCount();
			errors = e.getErrors();
		}
		assertEquals(12, errorCount);
		// error with wrapper tag
		assertTrue(message.contains("XML parsing failed"));
		assertTrue(
			message.contains(
				"Pattern file must have a wrapper <BytePatternSearchLibrary> tag to start."));
		// error with level tag
		assertTrue(message.contains("<Search> tag expected"));
		// ensure correct errors were collected
		assertEquals(
			"org.xml.sax.SAXParseException; Line: 54, Col: 11: Byte string is not an even size and cannot be parsed as Hex. Either adjust WordSize attribute to ASCII or zero-pad hex to make it well-formed. Skipping entire search item.",
			errors.get(8).toString());
	}

	/**
	 * Verify successful loading of provided sample file with slightly different schema.
	 * 
	 * @throws SAXException for parsing exception
	 */
	@Test
	public void testProvidedSamplePatternFile() throws SAXException {
		String currXmlFile =
			"ghidra/util/bytesearch/bytepatternsearch/dword_qword_for32bit_pattern.xml";
		File currTestXmlFile = ResourceManager.getResourceFile(currXmlFile);
		try {
			searchCollection = BpsXmlParser.parseSearchFile(currTestXmlFile, TaskMonitor.DUMMY);
		}
		catch (BpsXmlValidationException e) {
			fail("This file should parse without errors to prove compatibility");
		}
		BpsSearchItem item = searchCollection.get(0).getSearchItems().get(0);

		assertEquals("SearchItem was not parsed correctly.", "DIP32",
			item.getPatternName());
		assertEquals("Search tag name type isn't correct", "FunctionConstant",
			item.getPatterns().get(0).getName());
	}
}
