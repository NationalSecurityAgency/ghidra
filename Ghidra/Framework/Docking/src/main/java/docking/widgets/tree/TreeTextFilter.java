/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking.widgets.tree;

import ghidra.util.FilterTransformer;

import java.util.List;

import docking.widgets.filter.TextFilter;
import docking.widgets.tree.support.GTreeFilter;

public class TreeTextFilter implements GTreeFilter {

	private final TextFilter textFilter;
	private final FilterTransformer<GTreeNode> transformer;

	public TreeTextFilter(TextFilter textFilter, FilterTransformer<GTreeNode> transformer) {
		this.textFilter = textFilter;
		this.transformer = transformer;
	}

	@Override
	public boolean acceptsNode(GTreeNode node) {
		List<String> searchStrings = transformer.transform(node);
		int n = searchStrings.size();
		// using old fashion for loop to avoid object creation of iterator since this is called 
		// for each node in a tree (which can be hundreds of thousands)
		for (int i = 0; i < n; i++) {
			String text = searchStrings.get(i);
			if (textFilter.matches(text)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean showFilterMatches() {
		return true;
	}

}
