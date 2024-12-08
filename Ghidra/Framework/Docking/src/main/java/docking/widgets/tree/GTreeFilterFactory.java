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
package docking.widgets.tree;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.tree.TreePath;

import docking.widgets.filter.*;
import docking.widgets.tree.support.GTreeFilter;
import ghidra.util.FilterTransformer;

public class GTreeFilterFactory {

	private FilterOptions filterOptions;

	public GTreeFilterFactory() {
		this(new FilterOptions());
	}

	public GTreeFilterFactory(FilterOptions filterOptions) {
		this.filterOptions = filterOptions;
	}

	public FilterOptions getFilterOptions() {
		return filterOptions;
	}

	public GTreeFilter getTreeFilter(String text, FilterTransformer<GTreeNode> transformer) {
		GTreeFilter treeFilter = getBaseFilter(text, transformer);

		if (filterOptions.isInverted() && treeFilter != null) {
			treeFilter = new InvertedTreeFilter(treeFilter);
		}
		return treeFilter;
	}

	private GTreeFilter getBaseFilter(String text, FilterTransformer<GTreeNode> clientTransformer) {

		FilterTransformer<GTreeNode> transformer = clientTransformer;
		if (filterOptions.shouldUsePath()) {
			transformer = new PrependPathWrappingTransformer(clientTransformer);
		}

		if (filterOptions.isMultiterm() && text.trim().length() > 0) {
			return getMultiWordFilter(text, transformer);

		}
		TextFilter textFilter = filterOptions.getTextFilterFactory().getTextFilter(text);
		if (textFilter != null) {
			return new TreeTextFilter(textFilter, transformer);
		}
		return null;
	}

	private GTreeFilter getMultiWordFilter(String text,
			FilterTransformer<GTreeNode> transformer) {

		List<TextFilter> filters = new ArrayList<>();
		TermSplitter splitter = filterOptions.getTermSplitter();
		for (String term : splitter.split(text)) {
			TextFilter textFilter = filterOptions.getTextFilterFactory().getTextFilter(term);
			if (textFilter != null) {
				filters.add(textFilter);
			}
		}
		return new MultiTextFilterTreeFilter(filters, transformer,
			filterOptions.getMultitermEvaluationMode());
	}

	public Icon getFilterStateIcon() {
		return filterOptions.getFilterStateIcon();
	}

	/**
	 * A class that takes in a client node filter transformer and wraps it so that any text returned
	 * by the client will have the node path prepended. 
	 */
	private class PrependPathWrappingTransformer implements FilterTransformer<GTreeNode> {

		private ThreadLocal<List<String>> localizedResults = new ThreadLocal<>() {
			@Override
			protected List<String> initialValue() {
				return new ArrayList<>();
			}
		};

		private FilterTransformer<GTreeNode> delegate;

		PrependPathWrappingTransformer(FilterTransformer<GTreeNode> delegate) {
			this.delegate = delegate;
		}

		@Override
		public List<String> transform(GTreeNode t) {

			List<String> results = localizedResults.get();
			results.clear();

			TreePath treePath = t.getTreePath();
			Object[] elements = treePath.getPath();
			StringBuilder buffy = new StringBuilder();

			// ignore the leaf node, as text for that is generated separately
			int n = elements.length - 1;
			for (int i = 0; i < n; i++) {
				GTreeNode node = (GTreeNode) elements[i];
				buffy.append(node.getDisplayText()).append('/');
			}
			String parentPath = buffy.toString();

			List<String> delegateFilters = delegate.transform(t);
			for (String filterPiece : delegateFilters) {
				results.add(parentPath + filterPiece);
			}

			return results;
		}
	}
}
