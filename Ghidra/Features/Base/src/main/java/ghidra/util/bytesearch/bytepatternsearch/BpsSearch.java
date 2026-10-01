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
 * This class represents a collection of {@link BpsSearchItem}'s and their corresponding attributes
 * in support of Ghidra's Byte Pattern Searcher capability.
 * <P>
 * The design of the XML Parser and its supporting classes, as well as an explanation of the
 * required XML format can be found in {@link BpsXmlParser}.
 * <P>
 * The design of the Byte Pattern Searcher and its supporting sub-capabilities and classes can be
 * found in the "Search For Byte Patterns" page in the help viewer.
 * <P>
 * This class manages a Search, or list, of {@link BpsSearchItem} objects parsed from the
 * {@code <SearchItem>} tag. A search is populated by {@link BpsXmlParser} and referenced for
 * processing by downstream Byte Pattern Searcher components.
 *
 * <h4>Byte Pattern Search Configurations</h4>
 * <P>
 * <strong>Required Variables:</strong>
 * </p>
 * <ul>
 * <li>{@code searchName} &ndash; Name of the search collection.</li>
 * </ul>
 *
 * <P>
 * <strong>Optional Variables:</strong>
 * <ul>
 * <li>{@code description} &ndash; Text description of the pattern collection.</li>
 * <li>{@code submitter} &ndash; Name of the pattern contributor.</li>
 * </ul>
 * <strong>Note:</strong> additional attributes may be included on the {@code<Search>} tag, they
 * will be stored in a map for filtering and sorting downstream.
 */
public class BpsSearch {
	private List<BpsSearchItem> searchItems;
	private String searchName;
	private String id;
	private String description;
	private String submitter;
	private Map<String, String> additionalAttributes;

	/**
	 * Constructor.
	 * 
	 * @param searchName name identifying a Search
	 * @param generatedKey unique value across all BpsSearch and BpsSearchItem objects; used for
	 *            skipping patterns at the {@code <Search>} and {@code <SearchItem>} levels.
	 * @param searchItems belonging to this Search
	 */
	public BpsSearch(String searchName, String generatedKey, List<BpsSearchItem> searchItems) {
		this.searchName = searchName;
		this.id = generatedKey;
		this.searchItems = searchItems;
		this.additionalAttributes = new HashMap<>();
	}

	/**
	 * {@return the name of the Search}
	 */
	public String getSearchName() {
		return this.searchName;
	}

	/**
	 * {@return the search ID}
	 */
	public String getId() {
		return this.id;
	}

	/**
	 * {@return the list of search items belonging to the Search}
	 */
	public List<BpsSearchItem> getSearchItems() {
		return Collections.unmodifiableList(searchItems);
	}

	/**
	 * Set the description for the search.
	 * 
	 * @param description of the search
	 */
	void setDescription(String description) {
		this.description = description;
	}

	/**
	 * {@return the description for the search}
	 */
	public String getDescription() {
		return this.description;
	}

	/**
	 * Set the contributor's identification.
	 * 
	 * @param submitter who contributed the search
	 */
	void setSubmitter(String submitter) {
		this.submitter = submitter;
	}

	/**
	 * {@return the submitter's identification}
	 */
	public String getSubmitter() {
		return this.submitter;
	}

	/**
	 * Add attribute from the {@code<Search>} tag to the map for use downstream.
	 * 
	 * @param key attribute key
	 * @param value attribute value
	 */
	void setAttribute(String key, String value) {
		this.additionalAttributes.put(key, value);
	}

	/**
	 * {@return the additional attributes parsed from the {@code<Search>} tag}
	 */
	public Map<String, String> getAdditionalAttributes() {
		return Collections.unmodifiableMap(additionalAttributes);
	}

	@Override
	public String toString() {
		return this.searchName;
	}

}
