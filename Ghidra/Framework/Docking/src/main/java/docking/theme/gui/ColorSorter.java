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
package docking.theme.gui;

import java.awt.Color;
import java.util.Comparator;
import java.util.function.Function;

/**
 * Class for sorting colors by rgb values.  Each enum values changes the order of comparison for the
 * red, green, and blue color values.
 */
public enum ColorSorter implements Comparator<Color> {

	RGB("Red, Green, Blue", c -> c.getRed(), c -> c.getGreen(), c -> c.getBlue()),
	RBG("Red, Blue, Green", c -> c.getRed(), c -> c.getBlue(), c -> c.getGreen()),
	GRB("Green, Red, Blue", c -> c.getGreen(), c -> c.getRed(), c -> c.getBlue()),
	GBR("Green, Blue, Red", c -> c.getGreen(), c -> c.getBlue(), c -> c.getRed()),
	BRG("Blue, Red, Green", c -> c.getBlue(), c -> c.getRed(), c -> c.getGreen()),
	BGR("Blue, Green, Red", c -> c.getBlue(), c -> c.getGreen(), c -> c.getRed());

	private String name;
	private ColorFunction colorFunction1;
	private ColorFunction colorFunction2;
	private ColorFunction colorFunction3;

	ColorSorter(String name, ColorFunction f1, ColorFunction f2, ColorFunction f3) {
		this.name = name;
		colorFunction1 = f1;
		colorFunction2 = f2;
		colorFunction3 = f3;
	}

	public String getName() {
		return name;
	}

	public String toString() {
		return name;
	}

	@Override
	public int compare(Color o1, Color o2) {
		int v1 = colorFunction1.apply(o1);
		int v2 = colorFunction1.apply(o2);
		int result = v1 - v2;
		if (result == 0) {
			v1 = colorFunction2.apply(o1);
			v2 = colorFunction2.apply(o2);
			result = v1 - v2;
			if (result == 0) {
				v1 = colorFunction3.apply(o1);
				v2 = colorFunction3.apply(o2);
				result = v1 - v2;
			}
		}
		return result;
	}

	interface ColorFunction extends Function<Color, Integer> {
		//
	}
}
