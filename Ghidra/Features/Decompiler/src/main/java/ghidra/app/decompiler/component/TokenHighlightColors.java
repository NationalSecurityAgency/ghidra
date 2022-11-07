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
package ghidra.app.decompiler.component;

import java.awt.Color;
import java.util.*;

import generic.theme.Gui;

/**
 * A class to create and store colors related to token names
 */
public class TokenHighlightColors {

	private Map<String, Color> colorsByName = new HashMap<>();
	private List<Color> recentColors = new ArrayList<>();

	private Color generateColor() {

		float h = (float) Math.random(); // 0-360
		float s = .25f; // saturation; gray to full color; full color is too harsh for highlights
		float b = 1f; // brightness; black to full color
		if (Gui.isDarkTheme()) {
			s = .5f; // a bit more color against a dark background
			b = .5f; // less brightness, as the background is not as bright
		}

		return Color.getHSBColor(h, s, b);
	}

	public Color getColor(String text) {
		return colorsByName.computeIfAbsent(text, t -> generateColor());
	}

	public void setColor(String text, Color color) {
		colorsByName.put(text, color);
		recentColors.add(color);
	}

	public List<Color> getRecentColors() {
		return recentColors;
	}
}
