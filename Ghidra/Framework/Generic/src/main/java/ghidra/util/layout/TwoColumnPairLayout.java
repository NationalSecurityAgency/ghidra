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

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.LayoutManager;

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
		this(0,0,0,0);
	}
	
	public TwoColumnPairLayout(int verticalGap, int columnGap, int pairGap, int preferredValueColumnWidth) {
		super();
		this.verticalGap = verticalGap;
		this.columnGap = columnGap;
		this.pairGap = pairGap;
		this.preferredColumnWidth = preferredValueColumnWidth;
	}



	/**
	 * @see LayoutManager#addLayoutComponent(String, Component)
	 */
	public void addLayoutComponent(String name, Component comp) {}

	/**
	 * @see LayoutManager#removeLayoutComponent(Component)
	 */
	public void removeLayoutComponent(Component comp) {}

	/**
	 * @see LayoutManager#preferredLayoutSize(Container)
	 */
	public Dimension preferredLayoutSize(Container parent) {
		int rowHeight = getPreferredRowHeight(parent);
		int[] widths = getPreferredWidths(parent);
		
		int nRows = (parent.getComponentCount() + 3) / 4;
		Insets insets = parent.getInsets();
		Dimension d = new Dimension(0,0);
		int labelWidth = widths[0];
		int valueWidth = preferredColumnWidth == 0 ? widths[1] : preferredColumnWidth;
		
		d.width = 2*labelWidth + 2*valueWidth + columnGap + 2*pairGap + insets.left + insets.right;
		d.height = rowHeight *nRows + verticalGap * (nRows-1)  + insets.top + insets.bottom;
		return d;
	} 

	/**
	 * @see LayoutManager#minimumLayoutSize(Container)
	 */
	public Dimension minimumLayoutSize(Container parent) {
		return preferredLayoutSize(parent);
	}

	/**
	 * @see LayoutManager#layoutContainer(Container)
	 */
	public void layoutContainer(Container parent) {
		int rowHeight = getPreferredRowHeight(parent);
		int[] widths = getPreferredWidths(parent);

		Dimension d = parent.getSize();
		Insets insets = parent.getInsets();
		int width = d.width - (insets.left + insets.right);
		int x = insets.left;
		int y = insets.top;
		
		widths[1] = (width - 2*widths[0] - 2*pairGap - columnGap)/2;

		int n = parent.getComponentCount();
		for(int i=0;i<n;i++) {
			int index = i % 2;
			Component c = parent.getComponent(i);
			c.setBounds(x,y,widths[index],rowHeight);
			x += widths[index];
			x += (index == 0) ? pairGap : columnGap;
			if (i % 4 == 3) {
				y += rowHeight + verticalGap;
				x = insets.left;
			}
		}
	}

	int getPreferredRowHeight(Container parent) {
		int height = 0;
		
		int n = parent.getComponentCount();
		for(int i=0;i<n;i++) {
			Component c = parent.getComponent(i);
			height = Math.max(height, c.getPreferredSize().height);
		}
		return height;
	}
	int[] getPreferredWidths(Container parent) {
		int[] widths = new int[2];
		
		int n = parent.getComponentCount();
		for(int i=0;i<n;i++) {
			Component c = parent.getComponent(i);
			Dimension d = c.getPreferredSize();
			int index = i % 2;
			widths[index] = Math.max(widths[index], d.width);
		}
		return widths;	
	}
	
	
}
