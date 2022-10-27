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

import generic.Span;

public interface SpannedRenderer<N extends Number> {

	/**
	 * A closed interval on doubles
	 * 
	 * <p>
	 * This can only be a record of the endpoints. It does not have a domain implementation.
	 */
	record DoubleSpan(Span.Domain<Double, DoubleSpan> domain, Double min, Double max)
			implements Span<Double, DoubleSpan> {
		public DoubleSpan(double min, double max) {
			this(null, min, max);
		}

		@Override
		public String toString() {
			return "[" + min + ".." + max + "]";
		}
	}

	/**
	 * Validate the given span and convert its endpoints to doubles
	 * 
	 * @param fullSpan the span to validate
	 * @return the converted span
	 */
	public static DoubleSpan validateViewRange(Span<? extends Number, ?> fullSpan) {
		return new DoubleSpan(fullSpan.min().doubleValue(), fullSpan.max().doubleValue());
	}

	/**
	 * Set the span of the viewport
	 * 
	 * @param fullRange the span
	 */
	void setFullRange(Span<N, ?> fullRange);

	/**
	 * Get the span of the viewport
	 * 
	 * @return the span
	 */
	Span<N, ?> getFullRange();

	/**
	 * Get the span of the viewport with double endpoints
	 * 
	 * @return the span
	 */
	Span<Double, ?> getFullRangeDouble();

	/**
	 * Get the length of the span
	 * 
	 * @return the length
	 */
	double getSpan();

	/**
	 * Compute the horizontal pixel position of the given value
	 * 
	 * <p>
	 * This interpolates the given value linearly mapping it to a pixel. Pixel 0 is at the full
	 * span's lower endpoint and pixel {@code w} is at the full span's upper endpoint. If the given
	 * value falls outside the full span, it is clamped.
	 * 
	 * @param w the width of the viewport in pixels, i.e., {@link #getWidth()}
	 * @param val the value as in the span's domain, but as a double
	 * @return the horizontal pixel
	 */
	default int interpolate(int w, double val) {
		Span<Double, ?> fullRangeDouble = getFullRangeDouble();
		double span = getSpan();
		double lower = fullRangeDouble.min();
		if (val <= lower) {
			return 0;
		}
		if (val >= fullRangeDouble.max()) {
			return w;
		}
		double dif = val - lower;
		return (int) (dif / span * w);
	}

	/**
	 * Get the width of the renderer
	 * 
	 * @implNote this is often implemented by inheriting {@link Component#getWidth()}
	 * @return the width
	 */
	int getWidth();

	/**
	 * Get the height of the renderer
	 * 
	 * @implNote this is often implemented by inheriting {@link Component#getHeight()}
	 * @return the height
	 */
	int getHeight();

	/**
	 * Paint a given span
	 * 
	 * @param g the graphics, bound to a component
	 * @param range the span
	 */
	default void paintRange(Graphics g, Span<N, ?> range) {
		int width = getWidth();
		int height = getHeight();

		int x1 = range.minIsFinite()
				? interpolate(width, range.min().doubleValue())
				: 0;
		int x2 = range.maxIsFinite()
				? interpolate(width, range.max().doubleValue())
				: width;

		int y1 = height > 2 ? 1 : 0;
		int y2 = height > 2 ? height - 1 : height;

		g.fillRect(x1, y1, x2 - x1, y2 - y1);
	}
}
