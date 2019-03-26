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
package ghidra.app.util.viewer.util;

import ghidra.app.util.viewer.format.FieldHeader;

import java.awt.*;

import docking.widgets.indexedscrollpane.IndexedScrollPane;

public class ScrollpaneAlignedHorizontalLayout implements LayoutManager {

	private final IndexedScrollPane scroller;

	public ScrollpaneAlignedHorizontalLayout(IndexedScrollPane scroller) {
		this.scroller = scroller;
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
	public void layoutContainer(Container parent) {
		Rectangle viewportBorderBounds = scroller.getViewportBorderBounds();

		int n = parent.getComponentCount();
		Insets insets = parent.getInsets();
		int height = viewportBorderBounds.height;

		int x = insets.left;
		int y = viewportBorderBounds.y + getFieldHeaderOffset();

		for (int i = 0; i < n; i++) {
			Component c = parent.getComponent(i);
			int width = c.getPreferredSize().width;
			if (i == n - 1) {// the last gets the remaining width
				width = Math.max(width, parent.getWidth() - insets.right - x);
			}
			c.setBounds(x, y, width, height);
			x += width;
		}
	}

	private int getFieldHeaderOffset() {
		Component comp = scroller;
		Container parent = scroller.getParent();
		while (parent != null) {
			if (parent instanceof FieldHeader) {
				Rectangle bounds = comp.getBounds();
				return bounds.y;
			}
			comp = parent;
			parent = comp.getParent();
		}
		return 0;
	}

	@Override
	public Dimension minimumLayoutSize(Container parent) {
		return new Dimension(0, 0);
	}

	@Override
	public Dimension preferredLayoutSize(Container parent) {
		Insets insets = parent.getInsets();
		int n = parent.getComponentCount();
		int height = 0;
		int width = 0;

		for (int i = 0; i < n; i++) {
			Component c = parent.getComponent(i);
			Dimension d = c.getPreferredSize();
			width += d.width;
			height = Math.max(height, d.height);
		}
		return new Dimension(width + insets.left + insets.right, height + insets.top +
			insets.bottom);
	}

}
