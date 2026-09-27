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

import java.util.*;

/**
 * This class represents a parsed search item as used by the Byte Pattern Searcher capability within
 * Ghidra.
 * <P>
 * The design of the XML Parser and its supporting classes can be found in {@link BpsXmlParser}.
 * <P>
 * The design of the Byte Pattern Searcher and its supporting sub-capabilities and classes can be
 * found in the "Search For Byte Patterns" page in the help viewer.
 * <P>
 * This class manages the search item characteristics parsed from the {@code <SearchItem>} XML tag.
 *
 * <h4>Byte Pattern Search Item Configurations</h4>
 * <P>
 * <strong>Required Variables:</strong>
 * <ul>
 * <li>patternName &ndash; Name of the pattern for referencing.</li>
 * <li>wordSize &ndash; The pattern word size, resolved from the WordSize attribute from the
 * {@code<SearchItem>} tag.</li>
 * <li>searchType &ndash; The {@link BpsSearchType} strategy (table, constant, function, or ordered
 * function search, see {@link BpsSearchType}) which dictates how patterns are searched.</li>
 * <li>patterns &ndash; The {@code <BpsPattern>} collection of search byte sequences.</li>
 * </ul>
 *
 * <P>
 * <strong>Optional Variables:</strong>
 * <ul>
 * <li>description &ndash; Text explanation detailing the purpose of the search pattern.</li>
 * <li>submitter &ndash; The contributor who added this pattern to the {@link BpsSearch}.</li>
 * </ul>
 * <strong>Note:</strong> additional attributes may be included on the {@code<Search>} tag, they
 * will be stored in a map for filtering and sorting downstream.
 */
public class BpsSearchItem {

	private String patternName;
	private String id;
	private int wordSize;
	private BpsSearchType searchType;
	private List<BpsPattern> patterns;
	private String description;
	private String submitter;
	private Map<String, String> additionalAttributes;

	/**
	 * Constructor.
	 * 
	 * @param patternName name of pattern
	 * @param key unique key to facilitate skipping patterns at the {@code <SearchItem>} level
	 * @param wordSize word size for pattern bytes (e.g. byte-8, word-16, dword-32, qword-64)
	 * @param searchType how the bytes should be searched
	 */
	public BpsSearchItem(String patternName, String key, int wordSize, BpsSearchType searchType) {
		this.patternName = patternName;
		this.id = key;
		this.wordSize = wordSize;
		this.searchType = searchType;
		this.additionalAttributes = new HashMap<>();
	}

	/**
	 * {@return the pattern name}
	 */
	public String getPatternName() {
		return this.patternName;
	}

	/**
	 * {@return the search item's ID}
	 */
	public String getId() {
		return this.id;
	}

	/**
	 * {@return the pattern's word size}
	 */
	public int getWordSize() {
		return this.wordSize;
	}

	/**
	 * {@return the pattern's search type}
	 */
	public BpsSearchType getSearchType() {
		return this.searchType;
	}

	/**
	 * {@return the pattern's byte collection}
	 */
	public List<BpsPattern> getPatterns() {
		return Collections.unmodifiableList(this.patterns);
	}

	/**
	 * Set collection of byte arrays for the pattern.
	 * 
	 * @param patterns the byte arrays representing the pattern
	 */
	void setBytePatterns(List<BpsPattern> patterns) {
		this.patterns = new ArrayList<>(patterns);
	}

	/**
	 * Set the search item's description.
	 * 
	 * @param description of the search item
	 */
	void setDescription(String description) {
		this.description = description;
	}

	/**
	 * {@return the search item's description}
	 */
	public String getDescription() {
		return this.description;
	}

	/**
	 * Set pattern submitter identification.
	 * 
	 * @param submitter of the search item
	 */
	void setSubmitter(String submitter) {
		this.submitter = submitter;
	}

	/**
	 * {@return the submitter of the pattern}
	 */
	public String getSubmitter() {
		return this.submitter;
	}

	/**
	 * Add attribute to the list for use downstream.
	 * 
	 * @param key attribute key
	 * @param value attribute value
	 */
	void addAttribute(String key, String value) {
		this.additionalAttributes.put(key, value);
	}

	/**
	 * {@return the additional attributes map parsed from the {@code<SearchItem>} tag}
	 */
	public Map<String, String> getAdditionalAttributes() {
		return Collections.unmodifiableMap(this.additionalAttributes);
	}
}
