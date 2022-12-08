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
package ghidra.util.layout;

import java.awt.*;
import java.io.Serializable;

/**
  * Layout for two components laid out horizontally where the first component gets its preferred width
  * and the second component gets the remaining space up to its preferred width.
  */
public class RightSidedSquishyBuddyLayout implements LayoutManager, Serializable {

	private int hGap;
	private boolean rightAlign;

	public RightSidedSquishyBuddyLayout(int hGap) {
		this(hGap, false);
	}

	public RightSidedSquishyBuddyLayout(int hGap, boolean rightAlign) {
		this.rightAlign = rightAlign;
		this.hGap = hGap;
	}

	@Override
	public void addLayoutComponent(String name, Component comp) {
		// nothing to do
	}

	@Override
	public void removeLayoutComponent(Component comp) {
		// nothing to do
	}

	@Override
	public Dimension preferredLayoutSize(Container container) {
		Component[] components = container.getComponents();
		if (components.length == 0) {
			return new Dimension(0, 0);
		}
		int width = hGap;
		int height = 0;

		for (int i = 0; i < 2 && i < components.length; i++) {
			Component component = components[i];
			Dimension dim = component.getPreferredSize();
			width = width + dim.width;
			height = Math.max(height, dim.height);
		}

		Insets insets = container.getInsets();
		width += insets.left + insets.right;
		height += insets.top + insets.bottom;
		return new Dimension(width, height);
	}

	@Override
	public Dimension minimumLayoutSize(Container cont) {
		return preferredLayoutSize(cont);
	}

	@Override
	public void layoutContainer(Container container) {
		Component[] components = container.getComponents();
		if (components.length == 0) {
			return;
		}
		Insets insets = container.getInsets();
		if (components.length == 1) {
			Dimension size = components[0].getPreferredSize();
			components[0].setBounds(insets.left, insets.top, size.width, size.height);
			return;
		}

		Dimension containerSize = container.getSize();
		int width = containerSize.width - insets.left - insets.right;
		int height = containerSize.height - insets.top - insets.bottom;

		Dimension comp1PrefSize = components[0].getPreferredSize();
		Dimension comp2PrefSize = components[1].getPreferredSize();

		// always give comp1 its preferredWidth;

		int comp1Width = comp1PrefSize.width;
		int remainingWidth = Math.max(0, width - comp1Width - hGap);
		int comp2Width = Math.min(comp2PrefSize.width, remainingWidth);
		remainingWidth = Math.max(0, remainingWidth - comp2Width);

		int y = insets.top;

		int comp1X = insets.left;
		int comp2X = comp1X + comp1Width + hGap;
		if (rightAlign) {
			comp1X += remainingWidth;
			comp2X += remainingWidth;
		}

		components[0].setBounds(comp1X, y, comp1Width, height);
		components[1].setBounds(comp2X, y, comp2Width, height);

	}
}
