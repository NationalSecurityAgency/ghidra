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

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.apache.commons.lang3.Strings;
import org.xml.sax.*;

import ghidra.app.util.importer.MessageLog;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.*;

/**
 * This is the main class which parses pattern search XML files as used by the Byte Pattern Search
 * capability within Ghidra.
 * <P>
 * The design of the Byte pattern Searcher and its supporting sub-capabilities and classes can be
 * found in the "Search For Byte Patterns" page in the help viewer.
 * <P>
 * This class parses the provided byte pattern search XML files, populating corresponding Byte
 * Pattern Searcher objects: {@link BpsSearch},{@link BpsSearchItem}, and {@link BpsPattern} for
 * processing and searching downstream.
 * <P>
 * A search pattern XML file contains a set of byte patterns, organized into a simple hierarchy,
 * which contain specific meta-data details that will shape the search criteria. A full discussion
 * on the required XML schema can be found in the "Search For Byte Patterns" page in the help
 * viewer.
 * <P>
 * <strong>Note:</strong> All XML search documents must adhere to the structure outlined in the Byte
 * Pattern Search help file. Parse errors due to malformed XML or an XML structure that does not
 * follow the form, will result in accumulated parse errors which will be displayed once parsing has
 * completed.
 */
public class BpsXmlParser {

	private static final String BPS_LIBRARY = "library";
	private static final String NAME = "Name";
	private static final String SEARCH_TYPE = "SearchType";
	private static final String DATA_TYPE = "DataType";
	private static final String WORD_SIZE = "WordSize";
	private static final String SEARCH_ITEM = "SearchItem";
	private static int keyCounter; // Used for unique key generation within a pattern file

	/***
	 * Parse the provided XML file, generating a list of {@link BpsSearch} objects. A map is used to
	 * support the skipping of patterns at the {@code<Search>} and {@code<SearchItem>} levels.
	 * <P>
	 * All pattern files must have surrounding {@code<BytePatternSearchLibrary>} tags and adhere to
	 * the structure outlined in the Byte pattern Search help file.
	 * 
	 * @param searchFile XML file to be parsed
	 * @param monitor the task monitor
	 * 
	 * @return Byte pattern searches
	 * 
	 * @throws SAXException for malformed XML parse errors
	 */
	public static List<BpsSearch> parseSearchFile(File searchFile,
			TaskMonitor monitor) throws SAXException {

		try {
			return doParseSearchFile(searchFile, monitor);
		}
		catch (CancelledException e) {
			return List.of();
		}
	}

	private static List<BpsSearch> doParseSearchFile(File searchFile,
			TaskMonitor monitor) throws SAXException, CancelledException {

		XmlMessageLog log = new XmlMessageLog();
		AccumulatingErrorHandler errorHandler = new AccumulatingErrorHandler(log);
		XmlPullParser parser;
		keyCounter = 0; // Reset the key for each pattern file
		List<BpsSearch> searches = new ArrayList<>();

		try {
			parser = XmlPullParserFactory.create(searchFile, errorHandler, false);

			String parseName = parser.peek().getName().toLowerCase();
			if (!parseName.contains(BPS_LIBRARY)) {
				trackParseError(
					"Line: " + parser.getLineNumber() + ", Col: " + parser.getColumnNumber() +
						":  Pattern file must have a wrapper <BytePatternSearchLibrary> tag " +
						"to start.",
					log, errorHandler);
			}

			XmlElement startSearchElement = parser.start();

			// Each pattern file contains a collection of searches
			while (parser.peek().isStart()) {

				monitor.checkCancelled();

				String tag = parser.peek().getName();
				// This new version of Strings will ignore case by default
				if (Strings.CS.containsAny(tag, "Search", "Algorithm", "Family")) {
					List<BpsSearch> search = parseSearch(parser, log, errorHandler, monitor);
					searches.addAll(search);
				}
				else {
					trackParseError(
						"Line: " + parser.getLineNumber() + ", Col: " + parser.getColumnNumber() +
							": <Search> tag expected, current tag not supported: " + tag + ".",
						log, errorHandler);
					parser.discardSubTree(tag);
				}
			}

			parser.end(startSearchElement);
		}
		catch (SAXException | IOException e) {
			log.appendException(e);
			// Some severe fatal errors will break the parsing early, but standard violation
			// errors will be collected for review after parsing completes.
		}

		// Check if any errors were collected during the parsing process
		if (errorHandler.foundErrors()) {
			String combinedMessage = errorHandler.getExceptions()
					.stream()
					.map(exception -> exception.getMessage())
					.collect(Collectors.joining("\n"));

			// SAXParser exceptions do not allow for the inspection of each error encountered.
			// Since we are collecting errors as we go, allowing the parser to continue until
			// finished, we need more than a string message of the exception encountered - we need
			// access to the underlying exceptions for precise testing and error resolution.
			throw new BpsXmlValidationException(
				"XML parsing failed with " + errorHandler.getExceptions().size() + " errors:\n" +
					combinedMessage,
				errorHandler.getExceptions());
		}
		log.appendMsg("XML parsed successfully with zero errors");

		return searches;
	}

	/**
	 * Parse a {@code<Search>} tag and subsequent {@code <SearchItem>} tags. Searches are stored as
	 * {@link BpsSearch} objects and have 1 required tag attribute: "Name".
	 * <P>
	 * 
	 * @param parser the parser
	 * @param log message log
	 * @param errorHandler for standard violation XML errors
	 * @param monitor the task monitor
	 * 
	 * @return the search items
	 * 
	 * @throws SAXException for malformed XML parse errors
	 */
	private static List<BpsSearch> parseSearch(XmlPullParser parser, XmlMessageLog log,
			AccumulatingErrorHandler errorHandler, TaskMonitor monitor)
			throws SAXException, CancelledException {

		XmlElement searchStart = parser.start("Family", "Search");
		List<BpsSearch> searches = new ArrayList<>();

		// Search tags must have a "Name" attribute
		if (searchStart.hasAttribute(NAME)) {

			String name = searchStart.getAttribute(NAME);
			// Only 1 attribute to skip, gatherTagAttributes() requires this to be a list
			List<String> skipAttribute = List.of(NAME);
			Map<String, String> additionalAttributes =
				gatherTagAttributes(searchStart, skipAttribute);

			List<BpsSearchItem> searchItems = new ArrayList<>();
			while (parser.peek().isStart()) {

				monitor.checkCancelled();

				String tag = parser.peek().getName();
				if (!SEARCH_ITEM.equals(tag)) {
					trackParseError("Line: " + parser.getLineNumber() + ", Col: " +
						parser.getColumnNumber() + ": Tag not supported: " + tag +
						", <SearchItem> tag expected. Skipping subtree.", log, errorHandler);
					parser.discardSubTree(parser.next()); // Un-handled element
					continue;
				}

				BpsSearchItem item = parseSearchItem(parser, log, errorHandler);
				if (item != null) {
					searchItems.add(item);
				}
			}

			parser.end(searchStart);

			if (!searchItems.isEmpty()) {

				String parserName = parser.getName();
				String key = generateKey(parserName, name);
				BpsSearch search = new BpsSearch(name, key, searchItems);
				populateSearchAttributes(additionalAttributes, search, log);
				searches.add(search);
			}
			else {
				log.appendMsg("No valid <SearchItems> found for family: " + name + ", skipping.");
			}

		}
		else {
			trackParseError("Line: " + parser.getLineNumber() + ", Col: " +
				parser.getColumnNumber() +
				": All <Search> tags must contain a 'Name' attribute. Skipping this Search.",
				log, errorHandler);
			parser.discardSubTree(searchStart);
		}

		return searches;
	}

	/**
	 * The key helps differentiate between searches to support skipping patterns at the
	 * {@code<Search>} and {@code<SearchItem>} levels.
	 * <P>
	 * Example key: filename.xml_SearchName_1
	 * 
	 * @param fileName pattern file name
	 * @param name parsed {@code<Search>} or {@code<SearchItem>} name
	 * 
	 * @return generated key
	 */
	private static String generateKey(String fileName, String name) {
		return (String.format("%s_%s_%d", fileName, name, keyCounter++));
	}

	/**
	 * Unroll the mapping of key/value attribute pairs parsed from the XML {@code <Search>} tag and
	 * populate attribute values in {@link BpsSearch}.
	 * <P>
	 * NOTE: this is kept separate from buildSearchItem because there are some attributes between
	 * the two tags ({@code<Search>} and {@code<SearchItem>}) which overlap in name, but not in
	 * value. Specifically, both tags may contain "Description" and "Submitter" keys but their
	 * values will likely be different and need to be maintained separately. Keeping these separate
	 * requires two different managers to populate their corresponding object values.
	 * <P>
	 * 
	 * @param additionalTagAttributes extra parsed attributes on the {@code <Search>} tag
	 * @param search object that the tag attributes are assigned to
	 * @param log the XML log
	 */
	private static void populateSearchAttributes(
			Map<String, String> additionalTagAttributes, BpsSearch search,
			XmlMessageLog log) {

		for (String key : additionalTagAttributes.keySet()) {
			String value = additionalTagAttributes.get(key);
			switch (key) {
				case "Description":
					search.setDescription(value);
					break;

				case "Submitter":
					search.setSubmitter(value);
					break;

				default:
					log.appendMsg(
						"Unknown attribute on <Search> tag encountered: " + key + ", adding to " +
							"map for downstream use.");
					search.setAttribute(key, value);
					break;
			}
		}
	}

	/**
	 * Parse a {@code<SearchItem>} tag and subsequent {@code<Byte>} tags. SearchItems are stored as
	 * {@link BpsSearchItem} objects and have 3 required tag attributes: "Name", "WordSize", and
	 * "SearchType".
	 * 
	 * @param parser the parser
	 * @param log the XML log
	 * @param errorHandler for handling standard violation XML errors
	 * 
	 * @throws SAXException for malformed XML parse errors
	 */
	private static BpsSearchItem parseSearchItem(XmlPullParser parser,
			XmlMessageLog log, AccumulatingErrorHandler errorHandler) throws SAXException {

		XmlElement searchTag = parser.start("SearchItem");

		// Gather required attributes. "DataType" is a compatible substitute for WordSize
		if (!searchTag.hasAttribute(NAME) || !searchTag.hasAttribute(SEARCH_TYPE) ||
			(!searchTag.hasAttribute(WORD_SIZE) && !searchTag.hasAttribute(DATA_TYPE))) {
			trackParseError("Line: " + parser.getLineNumber() + ", Col: " +
				parser.getColumnNumber() +
				": All <SearchItem> tags must contain: 'Name', " +
				"'WordSize', and 'SearchType' attributes. Skipping this SearchItem.", log,
				errorHandler);
			parser.discardSubTree(searchTag);
			return null;
		}

		String name = searchTag.getAttribute(NAME);

		//  "DataType" is a compatible substitute for WordSize
		String targetValue =
			(searchTag.getAttribute(WORD_SIZE) != null) ? searchTag.getAttribute(WORD_SIZE)
					: searchTag.getAttribute(DATA_TYPE);
		int wordSize = lookUpWordSize(targetValue, log, errorHandler);

		String searchType = searchTag.getAttribute(SEARCH_TYPE);
		List<String> attributeSkipList = List.of(NAME, WORD_SIZE, SEARCH_TYPE);

		Map<String, String> additionalAttributes =
			gatherTagAttributes(searchTag, attributeSkipList);

		String fileName = parser.getName();
		BpsSearchItem searchItem = buildSearchItem(name, fileName, wordSize, searchType,
			additionalAttributes, log, errorHandler);

		List<BpsPattern> byteCollection =
			gatherSearchItemBytes(parser, wordSize, searchItem, log, errorHandler);

		if (byteCollection != null) {
			searchItem.setBytePatterns(byteCollection);
		}
		else {
			log.appendMsg(
				"No byte pattern found for SearchItem: " + name + " line: " +
					parser.getLineNumber() + ", skipping.");
		}
		parser.end(searchTag);

		return searchItem;
	}

	/**
	 * Generate {@link BpsSearchItem} object from parsed {@code<SearchItem>} tag.
	 * <P>
	 * 
	 * @param name SearchItem name
	 * @param wordSize byte pattern word size
	 * @param parsedSearchType the search type (e.g. function, constant, table, or orderedFunction)
	 *            default is constant search
	 * @param additionalAttributes parsed extra attributes on the {@code<SearchItem>} tag
	 * @param log the XML log
	 * @param errorHandler for handling invalid "searchType" attribute value
	 * 
	 * @return the search item
	 * 
	 * @throws SAXException for malformed XML parse errors
	 */
	private static BpsSearchItem buildSearchItem(String name, String filename, int wordSize,
			String parsedSearchType,
			Map<String, String> additionalAttributes, XmlMessageLog log,
			AccumulatingErrorHandler errorHandler) throws SAXException {

		BpsSearchType searchType;
		switch (parsedSearchType.toLowerCase()) {
			case "function":
				searchType = BpsSearchType.FUNCTION_SEARCH;
				break;
			case "constant":
				searchType = BpsSearchType.CONSTANT_SEARCH;
				break;
			case "table", "wholetable":
				searchType = BpsSearchType.TABLE_SEARCH;
				break;
			case "orderedfunction":
				searchType = BpsSearchType.ORDERED_FUNCTION_SEARCH;
				break;
			default:
				trackParseError("SearchType: '" + parsedSearchType + "' is unknown. " +
					"Using default constant search.", log, errorHandler);

				searchType = BpsSearchType.CONSTANT_SEARCH;
				break;
		}

		String generatedKey = generateKey(filename, name);
		BpsSearchItem searchItem =
			new BpsSearchItem(name, generatedKey, wordSize, searchType);

		for (String key : additionalAttributes.keySet()) {
			String value = additionalAttributes.get(key);
			switch (key) {
				case "Description":
					searchItem.setDescription(value);
					break;
				case "Submitter":
					searchItem.setSubmitter(value);
					break;
				default:
					log.appendMsg(
						"Unknown attribute on <SearchItem> tag encountered: " + key +
							", stored for use " +
							"downstream.");
					searchItem.addAttribute(key, value);
					break;
			}
		}
		return searchItem;
	}

	/**
	 * Parse each {@code <Byte>} sub tag. Bytes are currently assumed to be Hex or ASCII values and
	 * are parsed & stored accordingly. ASCII values are indicated in the XML as having a word size
	 * = -1. Each {@code<SearchItem>} has at least 1 {@code<Byte>} tag but could have hundreds of
	 * separate ones.
	 * <P>
	 * This method parses all {@code<byte>} tags and returns the list of {@link BpsPattern} objects
	 * which contain, not just the parsed byte string, but also metadata about the bytes.
	 * <P>
	 * <B>NOTE:</B> All byte patterns must be in big endian arrangement upon parsing.
	 * 
	 * @param parser the parser
	 * @param wordSize the byte pattern word size
	 * @param log XML log
	 * @param errorHandler for standard XML violation errors
	 * 
	 * @return list of byte patterns in the {@code<SearchItem>}
	 * 
	 * @throws SAXException for malformed hex errors
	 */
	private static List<BpsPattern> gatherSearchItemBytes(XmlPullParser parser, int wordSize,
			BpsSearchItem parentSearchItem, XmlMessageLog log,
			AccumulatingErrorHandler errorHandler) throws SAXException {

		List<BpsPattern> byteCollection = new ArrayList<>();

		while (parser.peek().isStart()) {
			XmlElement byteTag = parser.start();
			String tagName = byteTag.getName();

			// Ghidra's XML parser ties text content to XML elements (unlike other standard parsers)
			// so we must process the closing tag first in order to capture the text as that is
			// the tag that the text is attached to.
			byteTag = parser.end(byteTag);
			String byteString = byteTag.getText().trim();
			byteString = byteString.replaceAll("\\s", "");

			byte[] rawBytes;
			ByteBuffer buffer = null;
			if (wordSize == -1) { // indicates an ASCII value, handled differently
				rawBytes = byteString.getBytes();
				buffer = ByteBuffer.wrap(rawBytes);
			}
			else if (byteString.length() % 2 == 0) { // well-formed hex
				rawBytes = HexFormat.of().parseHex(byteString);
				buffer = ByteBuffer.wrap(rawBytes);

			}
			else {
				trackParseError("Line: " + parser.getLineNumber() + ", Col: " +
					parser.getColumnNumber() + ": Byte string is not an even size and " +
					"cannot be parsed as Hex. Either adjust WordSize attribute to " +
					"ASCII or zero-pad hex to make it well-formed. Skipping entire " +
					"search item.", log, errorHandler);

				// If even 1 <Byte> pattern is invalid, skip all <Byte> tags in the <SearchItem>
				// So that we don't perform a search on an incomplete <SearchItem>
				while (parser.peek().getName().equals("Bytes")) {
					parser.next();
				}
				return null; // force the skipping of this <SearchItem>
			}
			byteCollection.add(
				new BpsPattern(tagName, buffer, parentSearchItem, BpsTransformation.empty()));
		}
		return byteCollection;
	}

	/**
	 * Parse attribute values in the form of "Name"="Value". Any number of attributes may be
	 * included in the tag. Any attributes not outlined as required or optional will still be kept
	 * in a map for filtering downstream.
	 * <P>
	 * <B>NOTE:</B> All required attributes for a particular tag must be handled separately and are
	 * included in the skipList parameter so that they are not processed twice.
	 * <P>
	 * 
	 * @param currTag current XML element
	 * @param skipList required attributes to skip and not be parsed/stored twice
	 * 
	 * @return gathered tag attributes
	 */
	private static Map<String, String> gatherTagAttributes(XmlElement currTag,
			List<String> skipList) {

		Iterator<Entry<String, String>> attributes = currTag.getAttributeIterator();
		Map<String, String> additionalTags = new TreeMap<>();

		while (attributes.hasNext()) {
			Entry<String, String> attribute = attributes.next();
			String key = attribute.getKey();
			if (!skipList.contains(key)) {
				additionalTags.put(key, attribute.getValue());
			}
		}
		return additionalTags;
	}

	/**
	 * Word sizes in the XML are indicated as String word sizes. Translate these to int values for
	 * use later. ASCII is encoded with a value of -1 and an unknown data type is encoded as the
	 * default size of 16 (word) with an error message appended to the handler.
	 * <P>
	 * 
	 * @param wordSize parsed from "WordSize" attribute on {@code<SearchItem>} tag
	 * @param errorHandler track any errors encountered with parsing the word size
	 * @param log for logging progress
	 * 
	 * @return word size, default 16 indicates an invalid word size
	 * 
	 * @throws SAXException for invalid word size
	 */
	private static int lookUpWordSize(String wordSize, XmlMessageLog log,
			AccumulatingErrorHandler errorHandler) throws SAXException {
		switch (wordSize.toLowerCase()) {
			case "byte":
				return 8;
			case "word":
				return 16;
			case "dword":
				return 32;
			case "qword":
				return 64;
			case "ascii":
				return -1;
			default:
				trackParseError("Invalid word size encountered: " + wordSize + ". Default size " +
					"of 16 is being used.", log, errorHandler);
				return 16;
		}
	}

	/**
	 * Helper for generating error alerts during parsing.
	 * <P>
	 * 
	 * @param specificMessage error message specific to the problem encountered.
	 * @param log for tracking progress
	 * @param errorHandler for handling standard XML violation errors
	 * 
	 * @throws SAXException for handling malformed XML parse errors
	 */
	private static void trackParseError(String specificMessage,
			XmlMessageLog log, AccumulatingErrorHandler errorHandler) throws SAXException {
		log.appendMsg(specificMessage);
		errorHandler.error(new SAXParseException(specificMessage, null));
	}
}

/**
 * Custom exception class adds a field for holding collected errors for ease of access and testing
 * downstream.
 */
class BpsXmlValidationException extends SAXException {
	private final List<SAXParseException> errors = new ArrayList<>();

	BpsXmlValidationException(String message, List<SAXParseException> errors) {
		super(message);
		this.errors.addAll(errors);
	}

	// This allows us to test the number of errors caught directly
	int getErrorCount() {
		return errors.size();
	}

	// Let users inspect the raw errors if needed
	List<SAXParseException> getErrors() {
		return errors;
	}
}

/**
 * Custom ErrorHandler for XML parsing which keeps track of errors allowing parsing to complete
 * instead of breaking on minor infractions in the XML.
 */
class AccumulatingErrorHandler implements ErrorHandler {
	private MessageLog log;
	private final List<SAXParseException> exceptions = new ArrayList<>();

	AccumulatingErrorHandler(MessageLog log) {
		this.log = log;
	}

	@Override
	public void error(SAXParseException exception) throws SAXException {
		log.appendMsg(exception.getMessage());
		exceptions.add(exception);
	}

	@Override
	public void fatalError(SAXParseException exception) throws SAXException {
		log.appendMsg(exception.getMessage());
		exceptions.add(exception);
	}

	@Override
	public void warning(SAXParseException exception) throws SAXException {
		log.appendMsg(exception.getMessage());
		exceptions.add(exception);
	}

	/**
	 * {@return the list of exceptions found during parsing}
	 */
	public List<SAXParseException> getExceptions() {
		return exceptions;
	}

	/**
	 * {@return the error status of the parser}
	 */
	public boolean foundErrors() {
		return !exceptions.isEmpty();
	}
}
