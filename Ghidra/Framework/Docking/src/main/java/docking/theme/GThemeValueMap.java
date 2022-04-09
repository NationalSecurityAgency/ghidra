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
package docking.theme;

import java.util.*;

public class GThemeValueMap {
	Map<String, ColorValue> colorMap = new HashMap<>();
	Map<String, FontValue> fontMap = new HashMap<>();
	Map<String, IconValue> iconMap = new HashMap<>();

	public GThemeValueMap() {
	}

	public GThemeValueMap(GThemeValueMap initial) {
		load(initial);
	}

	public void addColor(ColorValue value) {
		if (value != null) {
			colorMap.put(value.getId(), value);
		}
	}

	public void addFont(FontValue value) {
		if (value != null) {
			fontMap.put(value.getId(), value);
		}
	}

	public void addIconPath(IconValue value) {
		if (value != null) {
			iconMap.put(value.getId(), value);
		}
	}

	public ColorValue getColor(String id) {
		return colorMap.get(id);
	}

	public FontValue getFont(String id) {
		return fontMap.get(id);
	}

	public IconValue getIcon(String id) {
		return iconMap.get(id);
	}

	public void load(GThemeValueMap valueMap) {
		valueMap.colorMap.values().forEach(v -> addColor(v));
		valueMap.fontMap.values().forEach(v -> addFont(v));
		valueMap.iconMap.values().forEach(v -> addIconPath(v));

	}

	public List<ColorValue> getColors() {
		return new ArrayList<>(colorMap.values());
	}

	public List<FontValue> getFonts() {
		return new ArrayList<>(fontMap.values());
	}

	public List<IconValue> getIconPaths() {
		return new ArrayList<>(iconMap.values());
	}

	public boolean containsColor(String id) {
		return colorMap.containsKey(id);
	}

	public boolean containsFont(String id) {
		return colorMap.containsKey(id);
	}

	public boolean containsIconPath(String id) {
		return colorMap.containsKey(id);
	}

	public Object size() {
		return colorMap.size() + fontMap.size() + iconMap.size();
	}
}
