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
 * LayoutManger for arranging components into exactly two columns.  
 */
public class TwoColumnPairLayout implements LayoutManager {
	private int verticalGap;
	private int columnGap;
	private int pairGap;
	private int preferredColumnWidth;

	/**
	 * Constructor for PairLayout.
	 */
	public TwoColumnPairLayout() {
		this(0, 0, 0, 0);
	}

	public TwoColumnPairLayout(int verticalGap, int columnGap, int pairGap,
			int preferredValueColumnWidth) {
		super();
		this.verticalGap = verticalGap;
		this.columnGap = columnGap;
		this.pairGap = pairGap;
		this.preferredColumnWidth = preferredValueColumnWidth;
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
		int rowHeight = getPreferredRowHeight(parent);
		int[] widths = getPreferredWidths(parent);

		int nRows = (parent.getComponentCount() + 3) / 4;
		Insets insets = parent.getInsets();
		Dimension d = new Dimension(0, 0);

		if (preferredColumnWidth > 0) {
			widths[1] = widths[3] = preferredColumnWidth;
		}

		d.width = widths[0] + widths[1] + widths[2] + widths[3] + columnGap + 2 * pairGap +
			insets.left + insets.right;
		d.height = rowHeight * nRows + verticalGap * (nRows - 1) + insets.top + insets.bottom;
		return d;
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
		int rowHeight = getPreferredRowHeight(parent);
		int[] widths = getPreferredWidths(parent);

		Dimension d = parent.getSize();
		Insets insets = parent.getInsets();
		int width = d.width - (insets.left + insets.right);
		int x = insets.left;
		int y = insets.top;

		int totalLabelWidth = widths[0] + widths[2];
		int padding = 2 * pairGap + columnGap;
		int totalValueWidth = (width - totalLabelWidth - padding);

		widths[1] = (totalValueWidth * widths[1]) / (widths[1] + widths[3]);
		widths[3] = totalValueWidth - widths[1];

		int n = parent.getComponentCount();
		for (int i = 0; i < n; i++) {
			int index = i % 4;
			Component c = parent.getComponent(i);
			c.setBounds(x, y, widths[index], rowHeight);
			x += widths[index];
			x += (index == 1) ? columnGap : pairGap;
			if (i % 4 == 3) {
				y += rowHeight + verticalGap;
				x = insets.left;
			}
		}
	}

	int getPreferredRowHeight(Container parent) {
		int height = 0;

		int n = parent.getComponentCount();
		for (int i = 0; i < n; i++) {
			Component c = parent.getComponent(i);
			height = Math.max(height, c.getPreferredSize().height);
		}
		return height;
	}

	int[] getPreferredWidths(Container parent) {
		int[] widths = new int[4];
		int n = parent.getComponentCount();
		for (int i = 0; i < n; i++) {
			Component c = parent.getComponent(i);
			Dimension d = c.getPreferredSize();
			int index = i % 4;
			widths[index] = Math.max(widths[index], d.width);
		}
		return widths;
	}

}
