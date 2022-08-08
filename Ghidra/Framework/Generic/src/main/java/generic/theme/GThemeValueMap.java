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

import java.io.File;
import java.net.URL;
import java.util.*;

import javax.swing.Icon;

import resources.ResourceManager;
import resources.icons.UrlImageIcon;

public class GThemeValueMap {
	protected Map<String, ColorValue> colorMap = new HashMap<>();
	protected Map<String, FontValue> fontMap = new HashMap<>();
	protected Map<String, IconValue> iconMap = new HashMap<>();

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

	public void addIcon(IconValue value) {
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
		valueMap.iconMap.values().forEach(v -> addIcon(v));

	}

	public List<ColorValue> getColors() {
		return new ArrayList<>(colorMap.values());
	}

	public List<FontValue> getFonts() {
		return new ArrayList<>(fontMap.values());
	}

	public List<IconValue> getIcons() {
		return new ArrayList<>(iconMap.values());
	}

	public boolean containsColor(String id) {
		return colorMap.containsKey(id);
	}

	public boolean containsFont(String id) {
		return fontMap.containsKey(id);
	}

	public boolean containsIcon(String id) {
		return iconMap.containsKey(id);
	}

	public Object size() {
		return colorMap.size() + fontMap.size() + iconMap.size();
	}

	public void clear() {
		colorMap.clear();
		fontMap.clear();
		iconMap.clear();
	}

	public boolean isEmpty() {
		return colorMap.isEmpty() && fontMap.isEmpty() && iconMap.isEmpty();
	}

	public void removeColor(String id) {
		colorMap.remove(id);
	}

	public GThemeValueMap getChangedValues(GThemeValueMap base) {
		GThemeValueMap map = new GThemeValueMap();
		for (ColorValue color : colorMap.values()) {
			if (!color.equals(base.getColor(color.getId()))) {
				map.addColor(color);
			}
		}
		for (FontValue font : fontMap.values()) {
			if (!font.equals(base.getFont(font.getId()))) {
				map.addFont(font);
			}
		}
		for (IconValue icon : iconMap.values()) {
			if (!icon.equals(base.getIcon(icon.getId()))) {
				map.addIcon(icon);
			}
		}
		return map;
	}

	public void removeFont(String id) {
		fontMap.remove(id);
	}

	public void removeIcon(String id) {
		iconMap.remove(id);
	}

	public Set<File> getExternalIconFiles() {
		Set<File> files = new HashSet<>();
		for (IconValue iconValue : iconMap.values()) {
			Icon icon = iconValue.getRawValue();
			if (icon instanceof UrlImageIcon urlIcon) {
				String originalPath = urlIcon.getOriginalPath();
				if (originalPath.startsWith(ResourceManager.EXTERNAL_ICON_PREFIX)) {
					URL url = urlIcon.getUrl();
					String filePath = url.getFile();
					if (filePath != null) {
						File iconFile = new File(filePath);
						if (iconFile.exists()) {
							files.add(iconFile);
						}
					}
				}
			}
		}
		return files;
	}

}
