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
package ghidra.util.layout;

import java.awt.*;

/**
 * LayoutManager for arranging components in a single row.  All components
 * retain their preferred widths, but are sized to the same height.
 */
public class HorizontalLayout implements LayoutManager {
	int hgap;

	/**
	 * Constructor for HorizontalLayout.
	 * @param hgap gap (in pixels) between components.
	 */
	public HorizontalLayout(int hgap) {
		this.hgap = hgap;
	}

	/**
	 * @see LayoutManager#addLayoutComponent(String, Component)
	 */
	@Override
	public void addLayoutComponent(String name, Component comp) {
	}

	/**
	 * @see LayoutManager#removeLayoutComponent(Component)
	 */
	@Override
	public void removeLayoutComponent(Component comp) {
	}

	/**
	 * @see LayoutManager#preferredLayoutSize(Container)
	 */
	@Override
	public Dimension preferredLayoutSize(Container parent) {
		Insets insets = parent.getInsets();
		int n = parent.getComponentCount();
		int height = 0;
		int width = n > 1 ? (n - 1) * hgap : 0;

		for (int i = 0; i < n; i++) {
			Component c = parent.getComponent(i);
			Dimension d = c.getPreferredSize();
			width += d.width;
			height = Math.max(height, d.height);
		}
		return new Dimension(width + insets.left + insets.right,
			height + insets.top + insets.bottom);
	}

	/**
	 * @see LayoutManager#minimumLayoutSize(Container)
	 */
	@Override
	public Dimension minimumLayoutSize(Container parent) {
		return preferredLayoutSize(parent);
	}

	/**
	 * @see LayoutManager#layoutContainer(Container)
	 */
	@Override
	public void layoutContainer(Container parent) {
		int n = parent.getComponentCount();
		Dimension d = parent.getSize();
		Insets insets = parent.getInsets();
		int height = d.height - insets.top - insets.bottom;

		int x = insets.left;
		int y = insets.top;

		for (int i = 0; i < n; i++) {
			Component c = parent.getComponent(i);
			d = c.getPreferredSize();
			c.setBounds(x, y, d.width, height);
			x += d.width + hgap;
		}
	}

}
