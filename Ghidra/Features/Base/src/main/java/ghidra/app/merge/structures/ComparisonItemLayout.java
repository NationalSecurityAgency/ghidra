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
package ghidra.app.merge.structures;

import java.awt.*;

/**
 * LayoutManager for arranging the labels for each column in a {@link ComparisonItem}.
 * The main idea here is that each type of item has a set of min/max widths associated with
 * each column that is used to align like types of items so that their fields line up.
 * <P> The tricky part is how to handle sizing them as the view is expanded or contracted.
 * Initially, all columns are given their minimum width and if the total is greater then the 
 * available width, the last columns are clipped. If the available width is greater than the
 * sum of the minimum widths, the extra width (10 at a time) is given to each column that still has
 * text wider than its current width. This is repeated until the extra width is used up or all 
 * columns have all the width they need to display their text. 
 * 
 */
public class ComparisonItemLayout implements LayoutManager {
	private static int HGAP = 5;
	private FontMetrics metrics;

	private ColumnWidths minMaxWidths = new ColumnWidths();
	private int[] adjustedWidths = new int[ComparisonItem.MAX_COLS];

	@Override
	public void addLayoutComponent(String name, Component comp) {
		// nothing to do
	}

	@Override
	public void removeLayoutComponent(Component comp) {
		// nothing to do
	}

	@Override
	public Dimension preferredLayoutSize(Container parent) {
		return minimumLayoutSize(parent);
	}

	@Override
	public Dimension minimumLayoutSize(Container parent) {
		int n = parent.getComponentCount();
		int width = 0;
		for (int i = 0; i < n; i++) {
			width += minMaxWidths.getMinWidth(i);
		}
		Insets insets = parent.getInsets();
		return new Dimension(width + insets.left + insets.right + 3 * HGAP, 0);
	}

	@Override
	public void layoutContainer(Container parent) {
		int n = parent.getComponentCount();
		Dimension d = parent.getSize();
		Insets insets = parent.getInsets();
		int width = d.width - insets.left - insets.right - 3 * HGAP;
		int height = d.height - insets.top - insets.bottom;
		computeWidths(width, n);

		int x = 0;
		int widthSoFar = 0;
		for (int i = 0; i < n; i++) {
			int compWidth = Math.min(adjustedWidths[i], width - widthSoFar);
			Component c = parent.getComponent(i);
			c.setBounds(x, 0, compWidth, height);
			x += compWidth + HGAP;
			widthSoFar += compWidth;
		}

	}

	private void computeWidths(int width, int componentCount) {
		int totalWidth = 0;
		int totalMaxWidth = 0;
		for (int i = 0; i < componentCount; i++) {
			int min = minMaxWidths.getMinWidth(i);
			int max = minMaxWidths.getMaxWidth(i);
			totalWidth += min;
			totalMaxWidth += max;
			adjustedWidths[i] = min;	// initialize columns widths to min size
		}

		if (width >= totalMaxWidth) {
			// set all columns to max
			for (int i = 0; i < componentCount; i++) {
				adjustedWidths[i] = minMaxWidths.getMaxWidth(i);
			}
			return;
		}
		// otherwise distribute extra width to those columns currently less than their max
		while (totalWidth < width && totalWidth < totalMaxWidth) {
			totalWidth = addToColumnWidths(totalMaxWidth - totalWidth, componentCount, metrics);
		}
	}

	private int addToColumnWidths(int extraWidth, int componentCount, FontMetrics metrics) {
		int totalWidth = 0;
		for (int i = 0; i < ComparisonItem.MAX_COLS; i++) {
			int maxWidth = minMaxWidths.getMaxWidth(i);
			int incrementAmount = Math.min(maxWidth - adjustedWidths[i], 10);
			adjustedWidths[i] += incrementAmount;
			extraWidth -= incrementAmount;
			totalWidth += adjustedWidths[i];
			if (extraWidth <= 0) {
				break;
			}
		}
		return totalWidth;
	}

	public void setColumnWidths(ColumnWidths widths) {
		this.minMaxWidths = widths;
	}

	static class ColumnWidths {
		private int[] minWidths = new int[ComparisonItem.MAX_COLS];
		private int[] maxWidths = new int[ComparisonItem.MAX_COLS];

		int getMinWidth(int column) {
			return minWidths[column];
		}

		int getMaxWidth(int column) {
			return maxWidths[column];
		}

		void addMinWidth(int column, int width) {
			minWidths[column] = Math.max(minWidths[column], width);
		}

		void addMaxWidth(int column, int width) {
			maxWidths[column] = Math.max(maxWidths[column], width);
		}
	}
}
