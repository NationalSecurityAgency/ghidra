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

import javax.swing.JComponent;

import docking.DockingWindowManager;
import docking.widgets.tree.support.GTreeFilter;

public interface GTreeFilterProvider {
	public JComponent getFilterComponent();

	public GTreeFilter getFilter();

	public void setEnabled(boolean enabled);

	public void setFilterText(String text);

	public String getFilterText();

	public void setDataTransformer(FilterTransformer<GTreeNode> transformer);

	public void loadFilterPreference(DockingWindowManager windowManager, String uniquePreferenceKey);

}
