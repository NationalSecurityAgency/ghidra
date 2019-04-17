/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.spaceview;

import java.awt.Color;
import java.awt.image.IndexColorModel;

public class GhidraColorMap {

	/*
	tier 1

	undefined (GRAY)
	zero (BLACK)
	low (DARK ORANGE)
	whitespace (PALE BLUE)
	digit (LIGHT BLUE)
	upper (LIGHT BLUE)
	lower (MED BLUE)
	symbol (DARK BLUE)
	high (DARK RED)
	full (-1, 255) (WHITE)

	tier 2

	float? (GREEN)
	double? (GREEN)
	int? (ORANGE)
	long? (ORANGE)
	instruction? (PINK)
	address? (YELLOW)

	tier 3

	SEAFOAM
	defined data (simple types)
	defined data (structs)
	defined data (unions)

	MAGENTA
	code (memory)
	code (flow)
	code (special)
	code (normal)

	PURPLE
	fun code (memory)
	fun code (flow)
	fun code (special)
	fun code (normal)

	RED
	error bookmarks

	tier 4

	selected (BRIGHT GREEN)
	highlighted (BRIGHT YELLOW)
	selected and highlighted (BRIGHT YELLOW GREEN)
	
	immutables needed:

	segmenting
	hilbert ordering
	maximuming
	from array
	cache
	iterator

	also:

	bijection from address to index in array space
	bijection from pixelspace to indexspace
	*/

	public IndexColorModel getColorModel() {
		Color[] colors =
			new Color[] { new Color(190, 255, 0), Color.red, new Color(128, 128, 128), Color.cyan,
				Color.magenta, };

		byte[] red = new byte[colors.length];
		byte[] grn = new byte[colors.length];
		byte[] blu = new byte[colors.length];
		for (int ii = 0; ii < colors.length; ++ii) {
			red[ii] = (byte) colors[ii].getRed();
			grn[ii] = (byte) colors[ii].getGreen();
			blu[ii] = (byte) colors[ii].getBlue();
		}
		IndexColorModel colorModel = new IndexColorModel(8, colors.length, red, grn, blu);

		return colorModel;
	}
}
