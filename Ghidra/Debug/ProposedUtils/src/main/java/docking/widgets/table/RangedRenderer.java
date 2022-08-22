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

import java.awt.Graphics;

import com.google.common.collect.Range;

public interface RangedRenderer<N extends Number & Comparable<N>> {

	public static Range<Double> validateViewRange(Range<? extends Number> fullRange) {
		if (!fullRange.hasLowerBound() || !fullRange.hasUpperBound()) {
			throw new IllegalArgumentException("Cannot have unbounded full range");
		}
		// I don't care to preserve open/closed, since it just specifies the view bounds
		return Range.closed(fullRange.lowerEndpoint().doubleValue(),
			fullRange.upperEndpoint().doubleValue());
	}

	void setFullRange(Range<N> fullRange);

	Range<N> getFullRange();

	Range<Double> getFullRangeDouble();

	double getSpan();

	default int interpolate(int w, double val) {
		Range<Double> fullRangeDouble = getFullRangeDouble();
		double span = getSpan();
		double lower = fullRangeDouble.lowerEndpoint();
		if (val <= lower) {
			return 0;
		}
		if (val >= fullRangeDouble.upperEndpoint()) {
			return w;
		}
		double dif = val - lower;
		return (int) (dif / span * w);
	}

	int getWidth();

	int getHeight();

	default void paintRange(Graphics g, Range<N> range) {
		int width = getWidth();
		int height = getHeight();

		int x1 = range.hasLowerBound()
				? interpolate(width, range.lowerEndpoint().doubleValue())
				: 0;
		int x2 = range.hasUpperBound()
				? interpolate(width, range.upperEndpoint().doubleValue())
				: width;

		int y1 = height > 2 ? 1 : 0;
		int y2 = height > 2 ? height - 1 : height;

		g.fillRect(x1, y1, x2 - x1, y2 - y1);
	}
}
