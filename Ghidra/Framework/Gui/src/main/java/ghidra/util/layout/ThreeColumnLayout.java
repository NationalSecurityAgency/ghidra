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
 * LayoutManger for arranging components into exactly three columns.  The first and last column
 * are statically sized to be the max preferred width of those columns.  The middle column's width
 * will vary as the panel is resized.
 * <p>
 * This layout works well for a panel that has rows of labels followed by a field and followed by
 * a trailing component like a button group. 
 */
public class ThreeColumnLayout implements LayoutManager {
	private static final int DEFAULT_VGAP = 5;
	private static final int DEFAULT_HGAP = 5;
	private static final int MIN_MAIN_COMP_WIDTH = 80;
	private int vgap;
	private int hgaps[];
	private int minPreferredWidths[] = new int[3];

	public ThreeColumnLayout() {
		this(DEFAULT_VGAP, new int[] { DEFAULT_HGAP, DEFAULT_HGAP },
			new int[] { 0, MIN_MAIN_COMP_WIDTH, 0 });
	}

	public ThreeColumnLayout(int vgap, int hgap1, int hgap2) {
		this(vgap, new int[] { hgap1, hgap2 }, new int[] { 0, MIN_MAIN_COMP_WIDTH, 0 });
	}

	public ThreeColumnLayout(int vgap, int hgaps[], int[] minPreferredWidths) {
		this.vgap = vgap;
		this.hgaps = hgaps;
		this.minPreferredWidths = minPreferredWidths;
	}

	@Override
	public void addLayoutComponent(String name, Component comp) {
		// empty
	}

	@Override
	public void removeLayoutComponent(Component comp) {
		// empty
	}

	@Override
	public Dimension preferredLayoutSize(Container parent) {
		Dimension d = new Dimension(0, 0);
		Insets insets = parent.getInsets();
		int[] widths = getPreferredWidths(parent);
		d.width =
			widths[0] + hgaps[0] + widths[1] + hgaps[1] + widths[2] + insets.left + insets.right;
		int n = parent.getComponentCount();
		for (int i = 0; i < n; i += 3) {
			Component c = parent.getComponent(i);
			int height = c.getPreferredSize().height;
			if (i < n - 2) {
				c = parent.getComponent(i + 1);
				height = Math.max(c.getPreferredSize().height, height);
				c = parent.getComponent(i + 2);
				height = Math.max(c.getPreferredSize().height, height);
			}
			d.height += height;
			d.height += vgap;
		}
		d.height -= vgap;
		d.height += insets.top + insets.bottom;
		return d;
	}

	@Override
	public Dimension minimumLayoutSize(Container parent) {
		return preferredLayoutSize(parent);
	}

	@Override
	public void layoutContainer(Container parent) {
		int[] widths = getPreferredWidths(parent);
		Dimension d = parent.getSize();
		Insets insets = parent.getInsets();
		int width = d.width - (insets.left + insets.right);
		int x = insets.left;
		int y = insets.top;
		int width1 = widths[0];
		int width3 = widths[2];
		int width2 =
			Math.max(minPreferredWidths[1], width - (width1 + width3 + hgaps[0] + hgaps[1]));

		int compCount = parent.getComponentCount();
		for (int i = 0; i < compCount; i += 3) {
			Component c = parent.getComponent(i);
			int height = c.getPreferredSize().height;
			if (i < compCount - 2) {
				Component c2 = parent.getComponent(i + 1);
				Component c3 = parent.getComponent(i + 2);
				height = Math.max(height, c2.getPreferredSize().height);
				height = Math.max(height, c3.getPreferredSize().height);

				c2.setBounds(x + width1 + hgaps[0], y, width2, height);
				c3.setBounds(x + width1 + hgaps[0] + width2 + hgaps[1], y, width3, height);
			}
			c.setBounds(x, y, width1, height);
			y += height + vgap;
		}
	}

	int[] getPreferredWidths(Container parent) {
		int[] widths = new int[3];
		System.arraycopy(minPreferredWidths, 0, widths, 0, 3);
		int n = parent.getComponentCount();
		for (int i = 0; i < n; i++) {
			Component c = parent.getComponent(i);
			Dimension d = c.getPreferredSize();
			int colIndex = i % 3;
			widths[colIndex] = Math.max(widths[colIndex], d.width);
		}
		return widths;
	}

}
