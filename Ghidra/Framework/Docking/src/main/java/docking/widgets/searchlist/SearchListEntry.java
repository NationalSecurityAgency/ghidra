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
package docking.widgets.searchlist;

/**
 * An record to hold the list item and additional information needed to properly render the item.
 * @param value the list item (T)
 * @param category the category for the item
 * @param showCategory true if this is the first item in the category and therefor the category
 * should be displayed.
 * @param drawSeparator if true, then a separator line should be drawn after this entry. This
 * should only be the case for the last entry in a category (and not the last category.)
 *
 * @param <T> the type of list items
 */
public record SearchListEntry<T>(T value, String category, boolean showCategory,
		boolean drawSeparator) {

}
