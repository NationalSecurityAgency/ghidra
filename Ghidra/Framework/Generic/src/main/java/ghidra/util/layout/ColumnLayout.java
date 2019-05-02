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
 * This layout arranges components in columns, putting as many components as possible in a
 * column and using as many columns as necessary.
 */
public class ColumnLayout implements LayoutManager {
	private int vgap;
	private int hgap;
	private int compWidth;
	private int compHeight;
	private int preferredNumCols;

	/**
	 * Constructs a new ColumnLayout
	 * @param hgap the gap (in pixels) between columns
	 * @param vgap the gap (in pixels) between rows
	 * @param preferredNumCols the prefered number of columns to use in the layout.
	 */
	public ColumnLayout(int hgap, int vgap, int preferredNumCols) {
		this.hgap = hgap;
		this.vgap = vgap;
		this.preferredNumCols = preferredNumCols;
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
		computeComponentSize(parent);

		int numRows = (n + preferredNumCols - 1) / preferredNumCols;
		int numCols = (n + numRows - 1) / numRows;

		int height = numRows * compHeight + (numRows - 1) * vgap;
		int width = numCols * compWidth + (numCols - 1) * hgap;
		Dimension d = new Dimension(width + insets.left + insets.right + 2,
			height + insets.top + insets.bottom + 2);

		return d;
	}

	/**
	 * @see LayoutManager#minimumLayoutSize(Container)
	 */
	@Override
	public Dimension minimumLayoutSize(Container parent) {
		Insets insets = parent.getInsets();
		return new Dimension(compWidth + insets.left + insets.right,
			compHeight + insets.top + insets.bottom);
	}

	/**
	 * @see LayoutManager#layoutContainer(Container)
	 */
	@Override
	public void layoutContainer(Container parent) {
		int n = parent.getComponentCount();
		if (n == 0) {
			return;
		}
		computeComponentSize(parent);
		Dimension d = parent.getSize();
		Insets insets = parent.getInsets();
		int parentWidth = d.width - insets.left - insets.right;
		int parentHeight = d.height - insets.top - insets.bottom;
		int maxRows = (parentHeight + vgap) / compHeight + vgap;
		if (maxRows == 0) {
			return;
		}
		int numCols = (n + maxRows - 1) / maxRows;
		int numRows = (n + numCols - 1) / numCols;
		int left = insets.left + (parentWidth - numCols * compWidth - (numCols - 1) * hgap) / 2;
		int top = insets.top;

		for (int i = 0; i < numRows; i++) {
			for (int j = 0; j < numCols; j++) {
				int x = left + j * (compWidth + hgap);
				int y = top + i * (compHeight + vgap);
				int k = j * numRows + i;
				if (k < n) {
					Component c = parent.getComponent(k);
					c.setBounds(x, y, compWidth, compHeight);
				}
			}
		}
	}

	private void computeComponentSize(Container parent) {
		int n = parent.getComponentCount();
		compWidth = 0;
		compHeight = 0;

		for (int i = 0; i < n; i++) {
			Component c = parent.getComponent(i);
			Dimension d = c.getPreferredSize();
			compWidth = Math.max(compWidth, d.width);
			compHeight = Math.max(compHeight, d.height);
		}
	}
}
