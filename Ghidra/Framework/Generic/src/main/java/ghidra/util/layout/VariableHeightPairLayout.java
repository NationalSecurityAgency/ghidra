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

/**
 * LayoutManger for arranging components into exactly two columns.  
 */
public class VariableHeightPairLayout implements LayoutManager {
	private static final int MIN_COMP_2 = 80;
	private int vgap;
	private int hgap;
	private int preferredWidth2;
	
	/**
	 * Constructor for PairLayout.
	 */
	public VariableHeightPairLayout() {
		this(0,0,MIN_COMP_2);
	}
	/**
	 * Constructs a new PairLayout.
	 * @param vgap the gap (in pixels) between rows.
	 * @param hgap the gap (in pixels) between the two columns.
	 */
	public VariableHeightPairLayout(int vgap, int hgap) {
		this(vgap, hgap, MIN_COMP_2);
	}
	
	/**
	 * Constructs a new PairLayout.
	 * @param vgap the gap (in pixels) between rows.
	 * @param hgap the gap (in pixels) between the two columns.
	 * @param preferredWidth2 specifies the preferred width of the second column.
	 */
	public VariableHeightPairLayout(int vgap, int hgap, int preferredWidth2) {
		this.vgap = vgap;
		this.hgap = hgap;
		this.preferredWidth2 = preferredWidth2;
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
		Dimension d = new Dimension(0,0);
		Insets insets = parent.getInsets();
		int[] widths = getPreferredWidths(parent);
		d.width = widths[0] + hgap + widths[1] + insets.left + insets.right;
		int n = parent.getComponentCount();
		for(int i=0;i<n;i+=2) {
			Component c = parent.getComponent(i);
			int height = c.getPreferredSize().height;
			if (i < n-1) {
				c = parent.getComponent(i+1);
				height = Math.max(c.getPreferredSize().height, height);
			}
			d.height += height;
			d.height += vgap;
		}
		d.height -= vgap;
		d.height += insets.top+insets.bottom;
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
		int[] widths = getPreferredWidths(parent);
		Dimension d = parent.getSize();
		Insets insets = parent.getInsets();
		int width = d.width - (insets.left + insets.right);
		int x = insets.left;
		int y = insets.top;
		int width1 = widths[0];
		int width2 = width - (width1 + hgap); 

		int nRows = parent.getComponentCount();
		for(int i=0;i<nRows;i+=2) {
			Component c = parent.getComponent(i);
			int height = c.getPreferredSize().height;
			if (i < nRows-1) {
				Component c2 = parent.getComponent(i+1);
				height = Math.max(height, c2.getPreferredSize().height);
				c2.setBounds(x+width1+hgap, y, width2, height);
			}
			c.setBounds(x, y, width1, height);
			y += height + vgap;
		}
	}

	int[] getPreferredWidths(Container parent) {
		int[] widths = new int[2];
		widths[1] = preferredWidth2;
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
