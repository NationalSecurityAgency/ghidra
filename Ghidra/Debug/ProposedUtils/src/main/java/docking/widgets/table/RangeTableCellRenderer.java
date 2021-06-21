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
package docking.widgets.table;

import java.awt.Component;
import java.awt.Graphics;

import com.google.common.collect.Range;

import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class RangeTableCellRenderer<N extends Number & Comparable<N>>
		extends AbstractGColumnRenderer<Range<N>> {

	protected Range<Double> doubleFullRange = Range.closed(0d, 1d);
	protected double span = 1;

	protected Range<N> fullRange;
	protected Range<N> dataRange;

	public static Range<Double> validateViewRange(Range<? extends Number> fullRange) {
		if (!fullRange.hasLowerBound() || !fullRange.hasUpperBound()) {
			throw new IllegalArgumentException("Cannot have unbounded full range");
		}
		// I don't care to preserve open/closed, since it just specifies the view bounds
		return Range.closed(fullRange.lowerEndpoint().doubleValue(),
			fullRange.upperEndpoint().doubleValue());
	}

	public void setFullRange(Range<N> fullRange) {
		this.fullRange = fullRange;
		this.doubleFullRange = validateViewRange(fullRange);
		this.span = this.doubleFullRange.upperEndpoint() - this.doubleFullRange.lowerEndpoint();
	}

	@Override
	public String getFilterString(Range<N> t, Settings settings) {
		return "";
	}

	@Override
	@SuppressWarnings("unchecked")
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {
		this.dataRange = (Range<N>) data.getValue();
		super.getTableCellRendererComponent(data);
		setText("");
		return this;
	}

	@Override
	protected void paintComponent(Graphics parentG) {
		super.paintComponent(parentG);
		if (dataRange == null) {
			return;
		}
		int width = getWidth();
		int height = getHeight();

		int x1 = dataRange.hasLowerBound()
				? interpolate(width, dataRange.lowerEndpoint().doubleValue())
				: 0;
		int x2 = dataRange.hasUpperBound()
				? interpolate(width, dataRange.upperEndpoint().doubleValue())
				: width;

		int y1 = height > 2 ? 1 : 0;
		int y2 = height > 2 ? height - 1 : height;

		Graphics g = parentG.create();
		g.setColor(getForeground());

		g.fillRect(x1, y1, x2 - x1, y2 - y1);
	}

	protected int interpolate(int w, double val) {
		double lower = doubleFullRange.lowerEndpoint();
		if (val <= lower) {
			return 0;
		}
		if (val >= doubleFullRange.upperEndpoint()) {
			return w;
		}
		double dif = val - lower;
		return (int) (dif / span * w);
	}

	public Range<N> getFullRange() {
		return fullRange;
	}
}
