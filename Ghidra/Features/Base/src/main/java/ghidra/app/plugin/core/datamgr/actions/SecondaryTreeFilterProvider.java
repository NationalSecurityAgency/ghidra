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
package ghidra.app.plugin.core.datamgr.actions;

import docking.widgets.tree.*;
import docking.widgets.tree.support.CombinedGTreeFilter;
import docking.widgets.tree.support.GTreeFilter;

/**
 * A filter that allows for an additional second filter.
 */
public class SecondaryTreeFilterProvider extends DefaultGTreeFilterProvider {

	private GTreeFilter secondaryFilter;

	SecondaryTreeFilterProvider(GTree tree, GTreeFilter secondaryFilter) {
		super(tree);
		this.secondaryFilter = secondaryFilter;
	}

	@Override
	public GTreeFilter getFilter() {
		GTreeFilter filter = super.getFilter();
		if (filter == null) {
			return secondaryFilter;
		}
		return new CombinedGTreeFilter(filter, secondaryFilter);
	}

	@Override
	public GTreeFilterProvider copy(GTree newTree) {
		// For now, we shouldn't need to copy the secondary filter.  It's current uses are to not
		// change the filter once it has been created.
		SecondaryTreeFilterProvider newProvider =
			new SecondaryTreeFilterProvider(newTree, secondaryFilter);
		return newProvider;
	}
}
