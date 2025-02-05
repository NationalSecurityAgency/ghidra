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
	 * Returns the component to place at the bottom of a GTree to provider filtering capabilities.
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
	 * <p>
	 * This is called when the tree is first made visible in the tool.  This is the chance for the
	 * filter to load any preferences and to add a preference supplier to the window manager.
	 * 
	 * @param windowManager the {@link DockingWindowManager} to load preferences from
	 */
	public void loadFilterPreference(DockingWindowManager windowManager);

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

	/**
	 * Creates a copy of this filter with all current filter settings.
	 * <P>
	 * This is meant to be used for GTrees that support creating a new copy.  
	 * <P>
	 * Note: Filter providers that do not support copying will return null from this method.
	 * 
	 * @param gTree the new tree for the new filter
	 * @return the copy
	 */
	public default GTreeFilterProvider copy(GTree gTree) {
		return null;
	}

	/**
	 * Activates this filter by showing it, if not visible, and then requesting focus in the filter
	 * text field. 
	 */
	public default void activate() {
		JComponent c = getFilterComponent();
		if (!c.isShowing()) {
			c.setVisible(true);
		}
		c.requestFocus();
	}

	/**
	 * Changes the visibility of the filter, make it not visible it if showing, showing it if
	 * not visible. 
	 */
	public default void toggleVisibility() {
		JComponent c = getFilterComponent();
		if (c.isShowing()) {
			c.setVisible(false);
		}
		else {
			c.setVisible(true);
			c.requestFocus();
		}
	}

	/**
	 * A method for subclasses to do any optional cleanup
	 */
	public default void dispose() {
		// stub
	}
}
