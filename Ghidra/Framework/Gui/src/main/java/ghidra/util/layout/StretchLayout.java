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
import java.io.Serializable;

/**
  * A layout manager that gives the affect of CENTER in BorderLayout.
  */
public class StretchLayout implements LayoutManager, Serializable {
	/** 
	 * @see java.awt.LayoutManager#addLayoutComponent(java.lang.String, java.awt.Component)
	 */
	@Override
	public void addLayoutComponent(String name, Component comp) {
	}

	/**
	 * @see java.awt.LayoutManager#removeLayoutComponent(java.awt.Component)
	 */
	@Override
	public void removeLayoutComponent(Component comp) {
	}

	/**
	 * @see java.awt.LayoutManager#preferredLayoutSize(java.awt.Container)
	 */
	@Override
	public Dimension preferredLayoutSize(Container container) {
		Component[] comps = container.getComponents();
		int maxWidth = 0;
		int maxHeight = 0;
		for (int i = 0; i < comps.length; i++) {
			Dimension size = new Dimension(comps[i].getPreferredSize());
			maxWidth = Math.max(maxWidth, size.width);
			maxHeight = Math.max(maxHeight, size.height);
		}
		Insets insets = container.getInsets();
		return new Dimension(maxWidth + insets.left + insets.right,
			maxHeight + insets.top + insets.bottom);

	}

	/**
	 * @see java.awt.LayoutManager#minimumLayoutSize(java.awt.Container)
	 */
	@Override
	public Dimension minimumLayoutSize(Container cont) {
		return preferredLayoutSize(cont);
	}

	/**
	 * @see java.awt.LayoutManager#layoutContainer(java.awt.Container)
	 */
	@Override
	public void layoutContainer(Container container) {
		Dimension containerSize = container.getSize();
		Insets insets = container.getInsets();
		int width = containerSize.width - insets.left - insets.right;
		int height = containerSize.height - insets.top - insets.bottom;
		if (width < 0)
			width = 0;
		if (height < 0)
			height = 0;
		try {
			Component[] comps = container.getComponents();
			for (int i = 0; i < comps.length; i++) {
				comps[i].setBounds(insets.left, insets.top, width, height);
			}
		}
		catch (Exception e) {
		}
	}
}
