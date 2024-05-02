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

import javax.swing.JComponent;

import docking.DockingWindowManager;
import docking.widgets.tree.support.GTreeFilter;
import ghidra.util.FilterTransformer;

/**
 * Interface for providing a filter for GTrees.
 */
public interface GTreeFilterProvider {
	/**
	 * Returns the component to place at the bottom of a GTree to provider filtering capabilites.
	 * @return the filter component
	 */
	public JComponent getFilterComponent();

	/**
	 * returns the {@link GTreeFilter} object to apply to the GTree whenever the filter component
	 * is manipulated
	 * @return the GTreeFilter to apply to the tree
	 */
	public GTreeFilter getFilter();

	/**
	 * Sets the active state for the filter component.
	 * @param enabled true, the filter component is enabled
	 */
	public void setEnabled(boolean enabled);

	/**
	 * Sets the filter text for the filter.
	 * @param text the text to filter on
	 */
	public void setFilterText(String text);

	/**
	 * Returns the current filter text.
	 * @return the current filter text
	 */
	public String getFilterText();

	/**
	 * Sets a {@link FilterTransformer} for preparing tree data to be filtered.
	 * @param transformer the transform for preparing tree data to be filtered
	 */
	public void setDataTransformer(FilterTransformer<GTreeNode> transformer);

	/**
	 * Loads any filter preferences that have been saved.
	 * @param windowManager the {@link DockingWindowManager} to load preferences from
	 * @param uniquePreferenceKey the preference key
	 */
	public void loadFilterPreference(DockingWindowManager windowManager,
			String uniquePreferenceKey);

	/**
	 * Sets an accessible name on the filter component. This prefix will be used to assign
	 * meaningful accessible names to the filter text field and the filter options button such
	 * that screen readers will properly describe them.
	 * <P>
	 * This prefix should be the base name that describes the type of items in the tree. 
	 * This method will then append the necessary information to name the text field and the button.
	 *
	 * @param namePrefix the accessible name prefix to assign to the filter component. For
	 * example if the tree contains fruits, then "Fruits" would be an appropriate prefix name.
	 */
	public void setAccessibleNamePrefix(String namePrefix);
}
