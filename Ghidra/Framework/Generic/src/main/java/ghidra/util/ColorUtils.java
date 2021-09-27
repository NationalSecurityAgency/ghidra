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
package ghidra.util;

import java.awt.Color;

public class ColorUtils {

	public static final float HUE_RED = 0.0f / 12;
	public static final float HUE_ORANGE = 1.0f / 12;
	public static final float HUE_YELLOW = 2.0f / 12;
	public static final float HUE_LIME = 3.0f / 12;
	public static final float HUE_GREEN = 4.0f / 12;
	public static final float HUE_PINE = 5.0f / 12;
	public static final float HUE_TURQUISE = 6.0f / 12;
	public static final float HUE_SAPPHIRE = 7.0f / 12;
	public static final float HUE_BLUE = 8.0f / 12;
	public static final float HUE_ROYAL = 9.0f / 12;
	public static final float HUE_PURPLE = 10.0f / 12;
	public static final float HUE_PINK = 11.0f / 12;

	public static Color deriveBackground(Color src, float hue, float sfact, float bfact) {
		float vals[] = new float[3];
		Color.RGBtoHSB(src.getRed(), src.getGreen(), src.getBlue(), vals);
		// Assign the requested hue without modification
		vals[0] = hue;
		// Multiply the source saturation by the desired saturation
		vals[1] *= sfact;
		// Compress the brightness toward 0.5
		vals[2] = 0.5f + (vals[2] - 0.5f) * bfact;

		// Compute the color
		return Color.getHSBColor(vals[0], vals[1], vals[2]);
	}

	public static Color deriveBackground(Color background, float hue) {
		return deriveBackground(background, hue, 1.0f, 0.9f);
	}

	public static Color deriveForeground(Color bg, float hue, float brt) {
		float[] vals = new float[3];
		Color.RGBtoHSB(bg.getRed(), bg.getGreen(), bg.getBlue(), vals);

		// Configure the brightness to make the colors sufficiently different.
		// The closer both saturations are to 0, the more different the brightnesses must be.
		// If the hues are similar, then the closer the saturations are to each other, the
		//   more different the brightnesses must be.
		// This can be addressed with some polar plotting:
		// Let the hue be the degree, and the saturation be the radius, so that the range
		// of values covers an area of a circle of radius 1. Let the circle be centered
		// at the origin. Plot the two colors and compute their distance in Euclidean
		// space.

		// Start by plotting the given background

		double bx = Math.cos(vals[0] * 2 * Math.PI) * vals[1];
		double by = Math.sin(vals[0] * 2 * Math.PI) * vals[1];

		// Now set the desired parameters and plot the foreground

		// Set the desired hue
		vals[0] = hue;

		// It's not pleasant to put two highly-saturated colors next to each other
		// Because of this restriction, we know that the maximum distance the two plotted
		// points can be from each other is 1, because their total distance to the center
		// is at most 1.
		vals[1] = 1.0f - vals[1];

		double fx = Math.cos(vals[0] * 2 * Math.PI) * vals[1];
		double fy = Math.sin(vals[0] * 2 * Math.PI) * vals[1];

		// Compute the distance for the given <hue,sat> points, which because of the
		// saturation restriction above, should have an upper bound of 1.0
		float hsdist = (float) Math.sqrt((bx - fx) * (bx - fx) + (by - fy) * (by - fy));

		// Heuristically, set the desired difference in brightness to one minus this distance
		float bdiff = 1 - hsdist;

		// Check if the requested brightness is sufficiently distant. If not, push it further
		// away, allowing it to flip to the other side if we hit a bound. If we hit a bound on
		// either side, then decide based on a reasonable middle. I find that 0.7 is about the
		// "middle" of brightness.
		if (Math.abs(vals[2] - brt) < bdiff) {
			if (brt > vals[2]) {
				brt = vals[2] + bdiff;
				if (brt > 1.0) {
					brt -= 2 * bdiff;
				}
			}
			else {
				brt = vals[2] - bdiff;
				if (brt < 0.0) {
					brt += 2 * bdiff;
				}
			}
			if (brt < 0.0 || brt > 1.0) {
				if (vals[2] < 0.7) {
					brt = 1.0f;
				}
				else {
					brt = 0.0f;
				}
			}
		}
		vals[2] = brt;

		for (int i = 0; i < 3; i++) {
			vals[i] = Math.min(Math.max(0.0f, vals[i]), 1.0f);
		}
		return Color.getHSBColor(vals[0], vals[1], vals[2]);
	}

	public static Color deriveForeground(Color bg, float hue) {
		return deriveForeground(bg, hue, 1.0f);
	}

	/**
	 * A method to produce a color (either black or white) that contrasts with the given color. This
	 * is useful for finding a readable foreground color for a given background.
	 * 
	 * @param color the color for which to find a contrast.
	 * @return the contrasting color.
	 */
	public static Color contrastForegroundColor(Color color) {
		float[] rgbs = new float[3];
		color.getRGBColorComponents(rgbs);
		int fR = rgbs[0] > 0.5 ? 0 : 1;
		int fG = rgbs[1] > 0.5 ? 0 : 1;
		int fB = rgbs[2] > 0.5 ? 0 : 1;

		// Note: the more accurate operation for calculating luminance is:
		// float gamma = 2.2;
		// float luminance = 0.2126 * pow(r, gamma) + 
		//                   0.7152 * pow(g, gamma) + 
		//                   0.0722 * pow(b, gamma);

		// less precise, faster calculation
		double luminance = 0.2126 * (fR * fR) + 0.7152 * (fG * fG) + 0.0722 * (fB * fB);
		Color foreground = Color.WHITE;
		if (luminance < 0.54) { // about half (a bit fudge, since we are approximating the pow())
			foreground = Color.BLACK;
		}
		return foreground;
	}

	/**
	 * Takes the first color, blending into it the second color, using the given ratio. A lower
	 * ratio (say .1f) signals to use very little of the first color; a larger ratio signals to use
	 * more of the first color.
	 * 
	 * @param c1 the first color
	 * @param c2 the second color
	 * @param ratio the amount of the first color to include in the final output
	 * @return the new color
	 */
	public static Color blend(Color c1, Color c2, float ratio) {

		float rgb1[] = new float[3];
		float rgb2[] = new float[3];
		c1.getColorComponents(rgb1);
		c2.getColorComponents(rgb2);

		float inverse = (float) 1.0 - ratio;

		//@formatter:off
		Color color = new Color(
			rgb1[0] * ratio + rgb2[0] * inverse, 
			rgb1[1] * ratio + rgb2[1] * inverse,
			rgb1[2] * ratio + rgb2[2] * inverse);
		//@formatter:on

		return color;
	}

	/**
	 * Blender of colors
	 */
	public static class ColorBlender {
		int r = 0;
		int g = 0;
		int b = 0;
		int a = 0;

		/**
		 * Add a color into the mixture, in a quantity proportional to its alpha value
		 * 
		 * @param color the color to mix
		 */
		public void add(Color color) {
			int ca = color.getAlpha();
			a += ca;
			r += ca * color.getRed();
			g += ca * color.getGreen();
			b += ca * color.getBlue();
		}

		/**
		 * Reset the mixture
		 */
		public void clear() {
			r = 0;
			g = 0;
			b = 0;
			a = 0;
		}

		/**
		 * Get the color of the current mixture
		 * 
		 * @param defaultColor the default (background) color, if the mixture has no color
		 * @return the resulting color
		 */
		public Color getColor(Color defaultColor) {
			if (a == 0) {
				return defaultColor;
			}
			return new Color(r / a, g / a, b / a);
		}
	}
}
