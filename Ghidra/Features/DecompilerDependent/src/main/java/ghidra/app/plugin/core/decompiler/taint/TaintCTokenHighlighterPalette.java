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
package ghidra.app.plugin.core.decompiler.taint;

import java.awt.Color;

public class TaintCTokenHighlighterPalette {

	private Color uninitializedColor;

	// The awt.Color class uses sRGB colors.
	private Color[] colors;

	public TaintCTokenHighlighterPalette(int sz) {
		// Using the constructor with ints.
		uninitializedColor = new Color(192, 192, 192);
		colors = new Color[sz];
		setGYRColorRange();
	}

	public int getSize() {
		if (colors == null) {
			return 0;
		}
		return colors.length;
	}

	public Color getDefaultColor() {
		return uninitializedColor;
	}

	/**
	 * The method that calls this will need to transform the decimal value into an integer in the appropriate range.
	 * That will be based on the sz parameter supplied to this constructor.
	 * @param i - index
	 * @return color
	 */
	public Color getColor(int i) {
		if (i < 0 || i >= colors.length) {
			// this will be a good way to detect errors.
			// if we want high and low to be represented by colors[0] and colors[colors.length-1] change this.
			return uninitializedColor;
		}
		return colors[i];
	}

	/**
	 * Establish the indexed color range; this is done 1 time.
	 * <p>
	 * <ul><li>
	 * Index 0:                 Green
	 * </li><li>
	 * Index colors.length / 2: Yellow
	 * </li><li>
	 * Index colors.length:     Red
	 * </li></ul>
	 * <p>
	 * <ul><li>
	 * Red: 1.0,0.0,0.0
	 * </li><li>
	 * Green: 0.0, 1.0, 0.0
	 * </li><li>
	 * Yellow: 1.0, 1.0, 0.0
	 * </li></ul>
	 */
	private void setGYRColorRange() {

		float red = 0.0f;
		float green = 1.0f;
		float blue = 0.0f;

		// since we are stepping through 2 colors, we double the rate of the step
		float step = (1.0f / (colors.length - 1)) * 10.0f;

		// red stays constant; green grows from 0.0 -> 1.0;
		for (int i = 0; i < colors.length; ++i) {

			colors[i] = new Color(red, green, blue);
			if (green == 1.0 && red < 1.0) {
				red += step;
				if (red > 1.0f)
					red = 1.0f;
			}
			else {
				// initially, green increases and the others stay constant.
				green -= step;
				if (green < 0.0)
					green = 0.0f;
			}
		}
	}
}
