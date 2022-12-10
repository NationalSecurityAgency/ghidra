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

/**
 * Class for storing colors, fonts, and icons by id
 */
public class GThemeValueMap {
	protected Map<String, ColorValue> colorMap = new HashMap<>();
	protected Map<String, FontValue> fontMap = new HashMap<>();
	protected Map<String, IconValue> iconMap = new HashMap<>();

	/**
	 * Constructs a new empty map.
	 */
	public GThemeValueMap() {
	}

	/**
	 * Constructs a new value map, populated by all the values in the given map. Essentially clones
	 * the given map.
	 * @param initial the set of values to initialize to
	 */
	public GThemeValueMap(GThemeValueMap initial) {
		load(initial);
	}

	/**
	 * Adds the {@link ColorValue} to the map. If a ColorValue already exists in the map with
	 * the same id, it will be replaced
	 * @param value the {@link ColorValue} to store in the map.
	 * @return the previous value for the color key or null if no previous value existed
	 */
	public ColorValue addColor(ColorValue value) {
		if (value != null) {
			return colorMap.put(value.getId(), value);
		}
		return null;
	}

	/**
	 * Adds the {@link FontValue} to the map. If a FontValue already exists in the map with
	 * the same id, it will be replaced
	 * @param value the {@link FontValue} to store in the map.
	 * @return the previous value for the font key or null if no previous value existed
	 */
	public FontValue addFont(FontValue value) {
		if (value != null) {
			return fontMap.put(value.getId(), value);
		}
		return null;
	}

	/**
	 * Adds the {@link IconValue} to the map. If a IconValue already exists in the map with
	 * the same id, it will be replaced
	 * @param value the {@link IconValue} to store in the map.
	 * @return the previous value for the icon key or null if no previous value existed
	 */
	public IconValue addIcon(IconValue value) {
		if (value != null) {
			return iconMap.put(value.getId(), value);
		}
		return null;
	}

	/**
	 * Returns the current {@link ColorValue} for the given id or null if none exists.
	 * @param id the id to look up a color for
	 * @return the current {@link ColorValue} for the given id or null if none exists.
	 */
	public ColorValue getColor(String id) {
		return colorMap.get(id);
	}

	/**
	 * Returns the current {@link FontValue} for the given id or null if none exists.
	 * @param id the id to look up a font for
	 * @return the current {@link FontValue} for the given id or null if none exists.
	 */
	public FontValue getFont(String id) {
		return fontMap.get(id);
	}

	/**
	 * Returns the current {@link IconValue} for the given id or null if none exists.
	 * @param id the id to look up a icon for
	 * @return the current {@link IconValue} for the given id or null if none exists.
	 */
	public IconValue getIcon(String id) {
		return iconMap.get(id);
	}

	/**
	 * Loads all the values from the given map into this map, replacing values with the 
	 * same ids.
	 * @param valueMap the map whose values are to be loaded into this map
	 */
	public void load(GThemeValueMap valueMap) {
		if (valueMap == null) {
			return;
		}
		valueMap.colorMap.values().forEach(v -> addColor(v));
		valueMap.fontMap.values().forEach(v -> addFont(v));
		valueMap.iconMap.values().forEach(v -> addIcon(v));
	}

	/**
	 * Returns a list of all the {@link ColorValue}s stored in this map.
	 * @return a list of all the {@link ColorValue}s stored in this map.
	 */
	public List<ColorValue> getColors() {
		return new ArrayList<>(colorMap.values());
	}

	/**
	 * Returns a list of all the {@link FontValue}s stored in this map.
	 * @return a list of all the {@link FontValue}s stored in this map.
	 */
	public List<FontValue> getFonts() {
		return new ArrayList<>(fontMap.values());
	}

	/**
	 * Returns a list of all the {@link IconValue}s stored in this map.
	 * @return a list of all the {@link IconValue}s stored in this map.
	 */
	public List<IconValue> getIcons() {
		return new ArrayList<>(iconMap.values());
	}

	/**
	 * Returns true if a {@link ColorValue} exists in this map for the given id.
	 * @param id the id to check
	 * @return true if a {@link ColorValue} exists in this map for the given id
	 */
	public boolean containsColor(String id) {
		return colorMap.containsKey(id);
	}

	/**
	 * Returns true if a {@link FontValue} exists in this map for the given id.
	 * @param id the id to check
	 * @return true if a {@link FontValue} exists in this map for the given id
	 */
	public boolean containsFont(String id) {
		return fontMap.containsKey(id);
	}

	/**
	 * Returns true if an {@link IconValue} exists in this map for the given id.
	 * @param id the id to check
	 * @return true if an {@link IconValue} exists in this map for the given id
	 */
	public boolean containsIcon(String id) {
		return iconMap.containsKey(id);
	}

	/**
	 * Returns the total number of color, font, and icon values stored in this map
	 * @return the total number of color, font, and icon values stored in this map
	 */
	public Object size() {
		return colorMap.size() + fontMap.size() + iconMap.size();
	}

	/**
	 * Clears all color, font, and icon values from this map
	 */
	public void clear() {
		colorMap.clear();
		fontMap.clear();
		iconMap.clear();
	}

	/**
	 * Returns true if there are not color, font, or icon values in this map
	 * @return true if there are not color, font, or icon values in this map
	 */
	public boolean isEmpty() {
		return colorMap.isEmpty() && fontMap.isEmpty() && iconMap.isEmpty();
	}

	/**
	 * removes any {@link ColorValue} with the given id from this map.
	 * @param id the id to remove
	 */
	public void removeColor(String id) {
		colorMap.remove(id);
	}

	/**
	 * removes any {@link FontValue} with the given id from this map.
	 * @param id the id to remove
	 */
	public void removeFont(String id) {
		fontMap.remove(id);
	}

	/**
	 * removes any {@link IconValue} with the given id from this map.
	 * @param id the id to remove
	 */
	public void removeIcon(String id) {
		iconMap.remove(id);
	}

	/**
	 * Returns a new {@link GThemeValueMap} that is only populated by values that don't exist
	 * in the give map.
	 * @param base the set of values (usually the default set) to compare against to determine 
	 * what values are changed.
	 * @return a new {@link GThemeValueMap} that is only populated by values that don't exist
	 * in the give map
	 */
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

	/**
	 * Gets the set of icon (.png, .gif) files that are used by IconValues that came from files
	 * versus resources in the classpath. These are the icon files that need to be included
	 * when exporting this set of values to a zip file.
	 * @return the set of icon (.png, .gif) files that are used by IconValues that came from files
	 * versus resources in the classpath
	 */
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

	@Override
	public int hashCode() {
		return Objects.hash(colorMap, fontMap, iconMap);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		GThemeValueMap other = (GThemeValueMap) obj;
		return Objects.equals(colorMap, other.colorMap) && Objects.equals(fontMap, other.fontMap) &&
			Objects.equals(iconMap, other.iconMap);
	}

	public void checkForUnresolvedReferences() {
		// attempting to get the values for all properties, will print warnings if they are unresolved
		for (ColorValue colorValue : colorMap.values()) {
			colorValue.get(this);
		}
		for (FontValue fontValue : fontMap.values()) {
			fontValue.get(this);
		}
		for (IconValue iconValue : iconMap.values()) {
			iconValue.get(this);
		}
	}

	/**
	 * Returns the set of all color ids in this map
	 * @return  the set of all color ids in this map
	 */
	public Set<String> getColorIds() {
		return colorMap.keySet();
	}

	/**
	 * Returns the set of all font ids in this map
	 * @return  the set of all font ids in this map
	 */
	public Set<String> getFontIds() {
		return fontMap.keySet();
	}

	/**
	 * Returns the set of all icon ids in this map
	 * @return  the set of all icon ids in this map
	 */
	public Set<String> getIconIds() {
		return iconMap.keySet();
	}
}
