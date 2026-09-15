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
 * This enum represents the type of search to be conducted as used by the Byte Pattern Searcher
 * capability within Ghidra.
 * <P>
 * The design of the Byte Pattern Searcher and its supporting sub-capabilities and classes can be
 * found in the "Search For Byte Patterns" page in the help viewer.
 * <P>
 * This enum manages the possible supported search types.
 * <P>
 * All {@link BpsSearchItem} objects will have a searchType which indicate how the
 * {@link BpsPattern} items should be searched for. A complete discussion of all search types can be
 * found in the "Search For Byte Patterns" page in the help viewer.
 */
public enum BpsSearchType {
	/**
	 * Table Search: byte patterns represent a table and must be found in the same order
	 *  as in the pattern file
	 */
	TABLE_SEARCH,

	/**
	 * Constant Search: byte patterns to be found anywhere and in any order in the program.
	 */
	CONSTANT_SEARCH,

	/**
	 * Function Search: byte patterns must all be found within the same function. 
	 */
	FUNCTION_SEARCH,

	/**
	 *  Ordered Function Search: byte patterns must all be found within the same function 
	 *  and also be found in the same order as in the pattern file.
	 */
	ORDERED_FUNCTION_SEARCH
}
