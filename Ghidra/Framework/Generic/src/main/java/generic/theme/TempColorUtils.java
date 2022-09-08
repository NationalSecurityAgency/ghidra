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
package generic.theme;

import java.awt.Color;

import ghidra.util.WebColors;

/**
 * A class to serve as a placeholder for migrating code.  After the migration is complete, uses
 * of this class can be removed, with the original code being restored in the process.
 */
public class TempColorUtils {

	public static Color fromRgb(int rgb) {
		return new Color(rgb);
	}

	public static Color fromRgba(int rgba) {
		return new Color(rgba, true);
	}

	public static Color fromRgb(int r, int g, int b) {
		return new Color(r, g, b);
	}

	public static Color fromRgba(int r, int g, int b, int a) {
		return new Color(r, g, b, a);
	}

	public static Color fromRgba(float r, float g, float b, float a) {
		return new Color(r, g, b, a);
	}

	public static Color withAlpha(Color c, int a) {
		return new Color(c.getRed(), c.getGreen(), c.getBlue(), a);
	}

	public static Color blend1(Color c1, Color c2) {
		int red = (c1.getRed() * 2 + c2.getRed()) / 3;
		int green = (c1.getGreen() * 2 + c2.getGreen()) / 3;
		int blue = (c1.getBlue() * 2 + c2.getBlue()) / 3;
		return new Color(red, green, blue);
	}

	public static Color blend2(Color c, int value) {
		int red = (c.getRed() + 3 * value) / 4;
		int green = (c.getGreen() + 3 * value) / 4;
		int blue = (c.getBlue() + 3 * value) / 4;
		return new Color(red, green, blue);
	}

	public static Color blend3(Color c1, Color c2) {
		int red = (c1.getRed() + c2.getRed()) / 2;
		int green = (c1.getGreen() + c2.getGreen()) / 2;
		int blue = (c1.getBlue() + c2.getBlue()) / 2;
		return new Color(red, green, blue);
	}

	public static Color blend4(Color c1, Color c2) {
		int red = (c1.getRed() * 3 + c2.getRed()) / 4;
		int green = (c1.getGreen() * 3 + c2.getGreen()) / 4;
		int blue = (c1.getBlue() * 3 + c2.getBlue()) / 4;
		return new Color(red, green, blue);
	}

	public static String toString(Color c) {
		return WebColors.toString(c, false);
	}
}
