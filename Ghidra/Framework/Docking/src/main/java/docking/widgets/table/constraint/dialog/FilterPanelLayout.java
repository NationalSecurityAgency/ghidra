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
package docking.widgets.table.constraint.dialog;

import java.awt.*;

/**
 * Specialized layout for the TableFilterDialog panels.  It is intended for a container with
 * exactly three components.  The first two components are sized to the width specified and the
 * last component gets its preferred width.  When laying out the components, the first two are
 * always sized to the specified width and the 3rd component gets all remaining size;
 */
public class FilterPanelLayout implements LayoutManager {

	private int componentWidth;
	private int hgap;

	/**
	 * Construct layout where first two components always have given width.
	 * @param componentWidth the width of each of the first two components.
	 * @param hgap the space between componennts.
	 */
	public FilterPanelLayout(int componentWidth, int hgap) {
		this.componentWidth = componentWidth;
		this.hgap = hgap;

	}

	@Override
	public void addLayoutComponent(String name, Component comp) {
		// do nothing
	}

	@Override
	public void removeLayoutComponent(Component comp) {
		// do nothing
	}

	@Override
	public Dimension preferredLayoutSize(Container parent) {
		return new Dimension(getPreferredWidth(parent), getPreferredHeight(parent));
	}

	private int getPreferredHeight(Container parent) {
		int n = parent.getComponentCount();
		int preferredHeight = 0;
		Insets insets = parent.getInsets();
		for (int i = 0; i < n; i++) {
			Component component = parent.getComponent(i);
			int height = component.getPreferredSize().height;
			preferredHeight = Math.max(preferredHeight, height);
		}
		return preferredHeight + insets.top + insets.bottom;
	}

	private int getPreferredWidth(Container parent) {
		int n = parent.getComponentCount();
		int lastWidth = (n == 3) ? parent.getComponent(2).getPreferredSize().width : 0;
		Insets insets = parent.getInsets();
		return insets.left + 2 * hgap + 2 * componentWidth + lastWidth;
	}

	@Override
	public Dimension minimumLayoutSize(Container parent) {
		return preferredLayoutSize(parent);
	}

	@Override
	public void layoutContainer(Container parent) {
		int n = parent.getComponentCount();
		Dimension d = parent.getSize();
		Insets insets = parent.getInsets();
		int x = insets.left;
		int y = insets.top;

		if (n > 0) {
			Component component = parent.getComponent(0);
			component.setBounds(x, y, componentWidth, component.getPreferredSize().height);
		}
		x += componentWidth + hgap;
		if (n > 1) {
			Component component = parent.getComponent(1);
			component.setBounds(x, y, componentWidth, component.getPreferredSize().height);
		}
		x += componentWidth + hgap;
		if (n > 2) {
			Component component = parent.getComponent(2);
			int remainingWidth = d.width - insets.left - insets.right - x;
			component.setBounds(x, y, remainingWidth, component.getPreferredSize().height);
		}
	}

}
