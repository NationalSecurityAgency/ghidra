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
package docking.widgets.table;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.filter.*;

public class DefaultTableTextFilterFactory<ROW_OBJECT>
		implements TableTextFilterFactory<ROW_OBJECT> {

	private final TextFilterFactory textFilterFactory;
	private final boolean inverted;
	private final FilterOptions filterOptions;

	public DefaultTableTextFilterFactory(FilterOptions filterOptions) {
		this.filterOptions = filterOptions;
		this.textFilterFactory = filterOptions.getTextFilterFactory();
		this.inverted = filterOptions.isInverted();
	}

	@Override
	public TableFilter<ROW_OBJECT> getTableFilter(String text,
			RowFilterTransformer<ROW_OBJECT> transformer) {

		TableFilter<ROW_OBJECT> tableFilter = getBaseFilter(text, transformer);

		if (inverted && tableFilter != null) {
			tableFilter = new InvertedTableFilter<>(tableFilter);
		}
		return tableFilter;
	}

	private TableFilter<ROW_OBJECT> getBaseFilter(String text,
			RowFilterTransformer<ROW_OBJECT> transformer) {
		if (filterOptions.isMultiterm() && text.trim().length() > 0) {
			return getMultiWordTableFilter(text, transformer);

		}
		TextFilter textFilter = textFilterFactory.getTextFilter(text);
		if (textFilter == null) {
			return null;
		}
		return new TableTextFilter<>(textFilter, transformer);

	}

	private TableFilter<ROW_OBJECT> getMultiWordTableFilter(String text,
			RowFilterTransformer<ROW_OBJECT> transformer) {

		List<TextFilter> filters = new ArrayList<>();
		TermSplitter splitter = filterOptions.getTermSplitter();
		for (String term : splitter.split(text)) {
			TextFilter textFilter = textFilterFactory.getTextFilter(term);
			if (textFilter != null) {
				filters.add(textFilter);
			}
		}
		return new MultiTextFilterTableFilter<>(filters, transformer,
			filterOptions.getMultitermEvaluationMode());
	}
}
