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
package ghidra.app.util.viewer.options;

import java.awt.Color;

import generic.theme.GColor;

public class ScreenElement {
	private String name;
	private String optionsName;
	private Color color;
	private GColor defaultColor;
	private int style;

	ScreenElement(String name, GColor defaultColor) {
		this(name, name, defaultColor, -1);
	}

	ScreenElement(String name, GColor defaultColor, int style) {
		this(name, name, defaultColor, style);
	}

	ScreenElement(String name, String optionsName, GColor defaultColor) {
		this(name, optionsName, defaultColor, -1);
	}

	ScreenElement(String name, String optionsName, GColor defaultColor, int style) {
		this.name = name;
		this.optionsName = optionsName;
		this.defaultColor = defaultColor;
		this.color = defaultColor;
		this.style = style;
	}

	public String getThemeColorId() {
		return defaultColor.getId();
	}

	public String getName() {
		return name;
	}

	public Color getColor() {
		return color;
	}

	public int getStyle() {
		return style;
	}

	public GColor getDefaultColor() {
		return defaultColor;
	}

	public void setColor(Color color) {
		this.color = color;
	}

	public void setStyle(int style) {
		this.style = style;
	}

	public String getColorOptionName() {
		return optionsName + " Color";
	}

	public String getStyleOptionName() {
		return optionsName + " Style";
	}

	@Override
	public String toString() {
		return name;
	}
}
