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
 * This layout arranges components in rows, putting as many components as possible on a
 * row and using as many rows as necessary. All components are sized the same, the largest width
 * and the largest height of all components.  The components prefer to be layout as close to 
 * a square as possible.
 */
public class RowColumnLayout implements LayoutManager {
	public static final int ROW = 0;
	public static final int COLUMN = 1;
	public static final int LEFT_TO_RIGHT = 0;
	public static final int TOP_TO_BOTTOM = 1;
	private int vgap;
	private int hgap;
	private int compWidth;
	private int compHeight;
	private int orientation;
	private int maxSize;
	private int fillOrder;

	/**
	 * Constructs a new RowColumnLayout
	 * @param hgap the gap (in pixels) between columns
	 * @param vgap the gap (in pixels) between rows
	 * @param orientation either ROW or COLUMN.  If ROW, components are layed out
	 * in rows up to prefered width, using as many rows a necessary.  If COLUMN, components are layed out
	 * in columns up to the prefered height, using as many columns as necessary.
	 * @param maxSize
	 */
	public RowColumnLayout(int hgap, int vgap, int orientation, int maxSize) {
		this.hgap = hgap;
		this.vgap = vgap;
		this.orientation = orientation;
		this.maxSize = maxSize;
		this.fillOrder = LEFT_TO_RIGHT;
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

		int numRows = 1;
		int numCols = 1;

		if (orientation == ROW) {
			int width = Math.max(maxSize - insets.left - insets.right, compWidth);
			numCols = (width + hgap) / (compWidth + hgap);
			numRows = (n + numCols - 1) / numCols;
			numCols = (n + numRows - 1) / numRows;
		}
		else {
			int height = Math.max(maxSize - insets.top - insets.bottom, compHeight);
			numRows = (height + vgap) / (compHeight + vgap);
			numCols = (n + numRows - 1) / numRows;
			numRows = (n + numCols - 1) / numCols;
		}

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

		computeComponentSize(parent);
		int n = parent.getComponentCount();
		Dimension d = parent.getSize();
		Insets insets = parent.getInsets();
		int parentWidth = d.width - insets.left - insets.right;
		int parentHeight = d.height - insets.top - insets.bottom;

		int numRows = 1;
		int numCols = 1;
		if (orientation == ROW) {
			numCols = (parentWidth + hgap) / (compWidth + hgap);
			if (numCols < 1) {
				numCols = 1;
			}
			numRows = (n + numCols - 1) / numCols;
			numCols = (n + numRows - 1) / numRows;
		}
		else {
			numRows = (parentHeight + vgap) / (compHeight + vgap);
			if (numRows < 1) {
				numRows = 1;
			}
			numCols = (n + numRows - 1) / numRows;
			numRows = (n + numCols - 1) / numCols;
		}

//		int left = insets.left + (parentWidth - numCols*compWidth- (numCols-1)*hgap)/2;
//		int top = insets.top + (parentHeight - numRows*compHeight - (numRows-1)*vgap)/2;
		int left = insets.left;
		int top = insets.top;

		for (int i = 0; i < numRows; i++) {
			for (int j = 0; j < numCols; j++) {
				int x = left + j * (compWidth + hgap);
				int y = top + i * (compHeight + vgap);
				int k = fillOrder == LEFT_TO_RIGHT ? i * numCols + j : j * numRows + i;
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

	/**
	 * @param maxSize
	 */
	public void setMaxSize(int maxSize) {
		this.maxSize = maxSize;
	}
}
