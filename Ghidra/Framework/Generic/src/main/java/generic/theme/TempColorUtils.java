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

	public static Color blend1(Color primary, Color secondary) {
		int red = (primary.getRed() * 2 + secondary.getRed()) / 3;
		int green = (primary.getGreen() * 2 + secondary.getGreen()) / 3;
		int blue = (primary.getBlue() * 2 + secondary.getBlue()) / 3;
		return new Color(red, green, blue);
	}

	public static Color blend2(Color c, int value) {
		int red = (c.getRed() + 3 * value) / 4;
		int green = (c.getGreen() + 3 * value) / 4;
		int blue = (c.getBlue() + 3 * value) / 4;
		return new Color(red, green, blue);
	}
}
