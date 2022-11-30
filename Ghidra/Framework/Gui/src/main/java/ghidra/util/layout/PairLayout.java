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
 * LayoutManger for arranging components into exactly two columns.  The right column and the 
 * left column may have differing widths.  Also, each row is the same height, 
 * which is the largest of all rows.
 */
public class PairLayout implements LayoutManager {
	private static final int MINIMUM_RIGHT_COLUMN_WIDTH = 80;
	private int vgap;
	private int hgap;

	private int preferredRightColumnWidth;
	private int leftColumnWidth;
	private int rowHeight;

	public PairLayout() {
		this(0, 0, MINIMUM_RIGHT_COLUMN_WIDTH);
	}

	/**
	 * Constructs a new PairLayout.
	 * @param vgap the gap (in pixels) between rows.
	 * @param hgap the gap (in pixels) between the two columns.
	 */
	public PairLayout(int vgap, int hgap) {
		this(vgap, hgap, MINIMUM_RIGHT_COLUMN_WIDTH);
	}

	/**
	 * Constructs a new PairLayout.
	 * @param vgap the gap (in pixels) between rows.
	 * @param hgap the gap (in pixels) between the two columns.
	 * @param minimumRightColumnWidth specifies the minimum width of the second column.
	 */
	public PairLayout(int vgap, int hgap, int minimumRightColumnWidth) {
		this.vgap = vgap;
		this.hgap = hgap;
		this.preferredRightColumnWidth = minimumRightColumnWidth;
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
		computeSizes(parent);
		int rowCount = (parent.getComponentCount() + 1) / 2;
		Insets insets = parent.getInsets();
		Dimension d = new Dimension(0, 0);
		d.width = leftColumnWidth + hgap + preferredRightColumnWidth + insets.left + insets.right;
		d.height = rowHeight * rowCount + vgap * (rowCount - 1) + insets.top + insets.bottom;
		return d;
	}

	@Override
	public Dimension minimumLayoutSize(Container parent) {
		// resulting min width equals the label column's (leftColumnWidth) width
		computeSizes(parent);
		int rowCount = (parent.getComponentCount() + 1) / 2;
		Insets insets = parent.getInsets();
		Dimension d = new Dimension(0, 0);
		d.width = leftColumnWidth + hgap + insets.left + insets.right;
		d.height = rowHeight * rowCount + vgap * (rowCount - 1) + insets.top + insets.bottom;
		return d;
	}

	@Override
	public void layoutContainer(Container parent) {
		computeSizes(parent);
		int componentCount = parent.getComponentCount();
		int rowCount = (componentCount + 1) / 2;
		Dimension d = parent.getSize();
		Insets insets = parent.getInsets();
		int width = d.width - (insets.left + insets.right);
		int x = insets.left;
		int y = insets.top;
		int rightColumnWidth = width - (leftColumnWidth + hgap);

		for (int i = 0; i < rowCount; i++) {
			Component leftColumnComponent = parent.getComponent(i * 2);
			leftColumnComponent.setBounds(x, y, leftColumnWidth, rowHeight);
			if (componentCount > i * 2 + 1) {
				Component rightColumnComponent = parent.getComponent(i * 2 + 1);
				rightColumnComponent.setBounds(x + leftColumnWidth + hgap, y, rightColumnWidth,
					rowHeight);
				y += rowHeight + vgap;
			}
		}
	}

	private void computeSizes(Container parent) {
		int componentCount = parent.getComponentCount();
		int rowCount = (componentCount + 1) / 2;

		leftColumnWidth = 0;
		rowHeight = 0;

		for (int i = 0; i < rowCount; i++) {
			Component leftColumnComponent = parent.getComponent(i * 2);
			Dimension d = leftColumnComponent.getPreferredSize();
			leftColumnWidth = Math.max(leftColumnWidth, d.width);
			rowHeight = Math.max(rowHeight, d.height);

			if (componentCount > i * 2 + 1) {
				Component rightColumnComponent = parent.getComponent(i * 2 + 1);
				d = rightColumnComponent.getPreferredSize();
				rowHeight = Math.max(rowHeight, d.height);
				preferredRightColumnWidth = Math.max(preferredRightColumnWidth, d.width);
			}
		}

	}

}
