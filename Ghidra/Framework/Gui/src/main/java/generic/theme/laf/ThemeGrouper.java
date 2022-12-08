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
package generic.theme.laf;

import java.awt.Color;
import java.awt.Font;
import java.util.*;

import javax.swing.LookAndFeel;
import javax.swing.plaf.basic.BasicLookAndFeel;

import generic.theme.*;

/**
 * Organizes UIDefaults color and font properties into groups so that every property doesn't
 * have its own direct value. The idea is that users can affect many properties that have the
 * same value by just changing the value for the group. For colors, the {@link LookAndFeel}s 
 * organize the properties internally and this class attempts to restore that organization 
 * as much as possible by using the values defined in the {@link BasicLookAndFeel} such as 
 * "control", "window", "controlShadlow", etc. The fonts don't appear to have any such internal
 * organization, so we created our own groups and used a lookAndFeel property to initialize each
 * group source value. Then whenever the font matched a group source value, the font is replace
 * with an indirect reference to the group source font value.
 * <p>
 * This class is sometimes sub-classed for a particular {@link LookAndFeel}. The subclass can
 * create new groups and mappings that are unique to that LookAndFeel.
 * 
 * Often, many of the various group source ids have the same color value. To try to group
 * properties as defined in BasicLookAndFeel, the preferred source ids are 
 * defined for each group. These will be tried first, but if a match isn't found among the
 * preferred sources, then all the sources will be searched for a match
 */
public class ThemeGrouper {
	private static String DEFAULT_FONT_GROUP_ID = "font.default";
	private static String BUTTON_FONT_GROUP_ID = "font.button";
	private static String TEXT_FONT_GROUP_ID = "font.text";
	private static String WIDGET_FONT_GROUP_ID = "font.widget";
	private static String COMPONENT_FONT_GROUP_ID = "font.component";
	private static String MENU_FONT_GROUP_ID = "font.menu";
	private static String MENU_ACCELERATOR_FONT_GROUP_ID = "font.menu.accelerator";

	static List<String> DEFAULT_FONT_SOURCE_PROPERTIES = List.of(
		DEFAULT_FONT_GROUP_ID,
		COMPONENT_FONT_GROUP_ID,
		WIDGET_FONT_GROUP_ID,
		TEXT_FONT_GROUP_ID,
		BUTTON_FONT_GROUP_ID,
		MENU_FONT_GROUP_ID,
		MENU_ACCELERATOR_FONT_GROUP_ID);

	// The list of color properties (defined in BasicLookAndFeel) that are used to populate 
	// other component specific colors.
	// The order is important. If any have the same color value, the one higher in the list is used.
	// Individual groups (buttons, menus, etc.) may define a different order that is more specific
	// to that group
	public static List<String> DEFAULT_COLOR_SOURCE_PROPERTIES = List.of(
		"control",
		"window",
		"activeCaption",
		"activeCaptionBorder",
		"activeCaptionText",
		"controlDkShadow",
		"controlHighlight",
		"controlLtHighlight",
		"controlShadow",
		"controlText",
		"desktp",
		"inactiveCaption",
		"inactiveCaptionBorder",
		"inactiveCaptionText",
		"info",
		"infoText",
		"menu",
		"menuText",
		"scrollbar",
		"scrollBarTrack",
		"text",
		"textHighlight",
		"textHighlightText",
		"textInactiveText",
		"textText",
		"windowBorder",
		"windowText");

	private static final String[] BUTTON_GROUP = {
		"Button",
		"ToggleButton",
		"RadioButton",
		"CheckBox"
	};
	private static final String[] MENU_GROUP = {
		"Menu",
		"MenuBar",
		"MenuItem",
		"PopupMenu",
		"RadioButtonMenuItem",
		"CheckBoxMenuItem"
	};
	private static final String[] TEXT_GROUP = {
		"TextField",
		"FormattedTextField",
		"PasswordField",
		"TextArea",
		"TextPane",
		"EditorPane"
	};
	private static final String[] WIDGET_GROUP = {
		"FileChooser",
		"ColorChooser",
		"ComboBox",
		"List",
		"Table",
		"Tree"
	};
	private static final String[] COMPONENT_GROUP = {
		"Desktop",
		"Panel",
		"InternalFrame",
		"Label",
		"OptionPane",
		"ProgressBar",
		"Separator",
		"ScrollBar",
		"ScrollPane",
		"Viewport",
		"Slider",
		"Spinner",
		"SplitPane",
		"TabbedPane",
		"TableHeader",
		"TitledBorder",
		"ToolBar",
		"ToolTip"
	};

	private static final String[] BUTTON_PREFERRED_SOURCES = {
		"control",
		"controlText",
		"controlShadow",
		"controlDkShadow",
		"controlHighlight",
		"controlLtHighlight"
	};
	private static final String[] MENU_PREFERRED_SOURCES = {
		"menu",
		"menuText",
		"textHighlightText",
		"textHighlight",
		"controlShadow",
		"controlDkShadow",
		"controlHighlight",
		"controlLtHighlight"
	};
	private static final String[] TEXT_PREFERRED_SOURCES = {
		"window",
		"text",
		"textText",
		"textInactiveText",
		"textHighlight",
		"textHighlightText",
		"controlShadow",
		"controlDkShadow",
		"controlHighlight",
		"controlLtHighlight"
	};
	private static final String[] WIDGET_PREFERRED_SOURCES = {
		"window",
		"textText",
		"textHighlight",
		"textHighlightText",
		"control",
		"controlShadow",
		"controlDkShadow",
		"controlHighlight",
		"controlLtHighlight"
	};
	private static final String[] COMPONENT_PREFERRED_SOURCES = {
		"control",
		"controlText",
		"controlShadow",
		"controlDkShadow",
		"controlHighlight",
		"controlLtHighlight",
		"textText",
		"textHighlight"
	};

	protected List<String> colorSourceProperties;
	protected List<String> fontSourceProperties;
	protected Set<PropertyGroup> groups;
	protected PropertyGroup buttonGroup = new PropertyGroup(BUTTON_GROUP, BUTTON_PREFERRED_SOURCES);
	protected PropertyGroup menuGroup = new PropertyGroup(MENU_GROUP, MENU_PREFERRED_SOURCES);
	protected PropertyGroup widgetGroup = new PropertyGroup(WIDGET_GROUP, WIDGET_PREFERRED_SOURCES);
	protected PropertyGroup textGroup = new PropertyGroup(TEXT_GROUP, TEXT_PREFERRED_SOURCES);
	protected PropertyGroup componentGroup =
		new PropertyGroup(COMPONENT_GROUP, COMPONENT_PREFERRED_SOURCES);

	public ThemeGrouper() {
		colorSourceProperties = new ArrayList<>(DEFAULT_COLOR_SOURCE_PROPERTIES);
		fontSourceProperties = new ArrayList<>(DEFAULT_FONT_SOURCE_PROPERTIES);
		groups = getPropertyGroups();
	}

	/**
	 * Replaces direct property values in the given GThemeValueMap with indirect references
	 * using the values from match source ids.
	 * @param values the values to search and replace source matches
	 */
	public void group(GThemeValueMap values) {
		initialize(values);
		Map<String, PropertyGroup> groupMap = buildGroupMap(values);
		groupColors(values, groupMap);
		groupFonts(values, groupMap);
	}

	/**
	 * Defines a new color id that will be used as the reference value for any specific color ids that
	 * have the same color value. This will allow all those specific colors to be changed at once.
	 * @param customGroupColorName name of a higher level group color id that will be used as the
	 * value for more specific color ids defined by the lookAndFeel.
	 * @param lookAndFeelSourceId the lookAndFeel color id whose value will be used as the value
	 * for the new custom group color id
	 * @param values the map where we store the default theme value mappings
	 */
	protected void defineCustomColorGroup(String customGroupColorName, String lookAndFeelSourceId,
			GThemeValueMap values) {

		colorSourceProperties.add(customGroupColorName);
		ColorValue colorValue = values.getColor(lookAndFeelSourceId);
		if (colorValue != null) {
			Color color = colorValue.get(values);
			values.addColor(new ColorValue(customGroupColorName, color));
		}
	}

	/**
	 * Defines a new font id that will be used as the reference value for any specific font ids that
	 * have the same font value. This will allow all those specific fonts to be changed at once.
	 * @param customGroupFontName name of a higher level group font id that will be used as the
	 * value of more specific font ids defined by the lookAndFeel.
	 * @param lookAndFeelSourceId the lookAndFeel font id whose value will be used as the value
	 * for the new custom group font id
	 * @param values the map where we store the default theme value mappings
	 */
	protected void defineCustomFontGroup(String customGroupFontName, String lookAndFeelSourceId,
			GThemeValueMap values) {
		fontSourceProperties.add(customGroupFontName);
		FontValue fontValue = values.getFont(lookAndFeelSourceId);
		if (fontValue != null) {
			Font font = fontValue.get(values);
			values.addFont(new FontValue(customGroupFontName, font));
		}
	}

	private void groupColors(GThemeValueMap values, Map<String, PropertyGroup> groupMap) {
		Set<String> skip = new HashSet<>(colorSourceProperties); // we don't want to map sources
		Map<Integer, String> defaultColorMapping = buildColorToSourceMap(values);
		// try to map each color property to a source property (e.g., Button.background -> control)
		for (ColorValue colorValue : values.getColors()) {
			String id = colorValue.getId();
			if (colorValue.isIndirect() || skip.contains(id)) {
				continue;
			}
			PropertyGroup group = groupMap.get(getComponentName(id));
			int rgb = colorValue.getRawValue().getRGB();
			String sourceProperty = group == null ? null : group.getSourceProperty(rgb);
			if (sourceProperty == null) {
				sourceProperty = defaultColorMapping.get(rgb);
			}

			if (sourceProperty != null) {
				values.addColor(new ColorValue(id, sourceProperty));
			}
		}
	}

	private void groupFonts(GThemeValueMap values, Map<String, PropertyGroup> groupMap) {
		Set<String> skip = new HashSet<>(fontSourceProperties); // we don't want to map sources
		Map<Font, String> defaultFontMapping = buildFontToSourceMap(values);

		// try to map each color property to a source property (e.g., Button.background -> control)
		for (FontValue fontValue : values.getFonts()) {
			String id = fontValue.getId();
			if (fontValue.isIndirect() || skip.contains(id)) {
				continue;
			}
			Font font = fontValue.getRawValue();
			PropertyGroup group = groupMap.get(getComponentName(id));
			String sourceProperty = group == null ? null : group.getSourceProperty(font);
			if (sourceProperty == null) {
				sourceProperty = defaultFontMapping.get(font);
			}
			if (sourceProperty != null) {
				values.addFont(new FontValue(id, sourceProperty));
			}
		}
	}

	private void initialize(GThemeValueMap values) {
		// initialized default font to the Panel's font
		FontValue defaultFontValue = values.getFont("Panel.font");
		if (defaultFontValue != null) {
			values.addFont(new FontValue(DEFAULT_FONT_GROUP_ID, defaultFontValue.get(values)));
		}

		// initialize the default group fonts to a font from an exemplar property in that group
		initializeFontGroup(buttonGroup, BUTTON_FONT_GROUP_ID, "Button.font", values);
		initializeFontGroup(textGroup, TEXT_FONT_GROUP_ID, "TextField.font", values);
		initializeFontGroup(widgetGroup, WIDGET_FONT_GROUP_ID, "Table.font", values);
		initializeFontGroup(componentGroup, COMPONENT_FONT_GROUP_ID, "Panel.font", values);
		initializeFontGroup(menuGroup, MENU_FONT_GROUP_ID, "Menu.font", values);
		initializeFontGroup(menuGroup, MENU_ACCELERATOR_FONT_GROUP_ID, "Menu.acceleratorFont",
			values);
	}

	private void initializeFontGroup(PropertyGroup group, String fontGroupId, String exemplarId,
			GThemeValueMap values) {
		FontValue fontValue = values.getFont(exemplarId);
		if (fontValue != null) {
			Font font = fontValue.getRawValue();
			values.addFont(new FontValue(fontGroupId, font));
			group.addFontMapping(font, fontGroupId);
		}
	}

	private Set<PropertyGroup> getPropertyGroups() {
		Set<PropertyGroup> set = new HashSet<>();
		set.add(buttonGroup);
		set.add(menuGroup);
		set.add(textGroup);
		set.add(widgetGroup);
		set.add(componentGroup);
		return set;
	}

	private Map<String, PropertyGroup> buildGroupMap(GThemeValueMap values) {
		Map<String, PropertyGroup> map = new HashMap<>();
		for (PropertyGroup group : groups) {
			group.initialize(values);
			group.populateGroupMap(map);
		}
		return map;
	}

	private String getComponentName(String id) {
		int dotIndex = id.indexOf(".");
		if (dotIndex < 0) {
			return id;
		}
		return id.substring(0, dotIndex);
	}

	private Map<Integer, String> buildColorToSourceMap(GThemeValueMap values) {
		Map<Integer, String> colorMapping = new HashMap<>();
		ArrayList<String> reversed = new ArrayList<>(colorSourceProperties);
		Collections.reverse(reversed);
		// go through in reverse order so that values at the top of the list have precedence
		// if multiple propertyBases have the save value.
		for (String propertyBase : reversed) {
			ColorValue colorValue = values.getColor(propertyBase);
			if (colorValue != null) {
				Color color = colorValue.get(values);
				colorMapping.put(color.getRGB(), propertyBase);
			}
		}
		return colorMapping;
	}

	private Map<Font, String> buildFontToSourceMap(GThemeValueMap values) {
		Map<Font, String> fontMapping = new HashMap<>();
		ArrayList<String> reversed = new ArrayList<>(fontSourceProperties);
		Collections.reverse(reversed);
		// go through in reverse order so that values at the top of the list have precedence
		// if multiple propertyBases have the save value.
		for (String propertyBase : reversed) {
			FontValue fontValue = values.getFont(propertyBase);
			if (fontValue != null) {
				Font font = fontValue.get(values);
				fontMapping.put(font, propertyBase);
			}
		}
		return fontMapping;
	}

	static class PropertyGroup {
		private Set<String> groupComponents = new HashSet<>();
		private List<String> preferredPropertyColorSources = new ArrayList<>();
		private Map<Integer, String> colorMapping;
		private Map<Font, String> fontMapping = new HashMap<>();

		PropertyGroup(String[] components, String[] perferredSources) {
			addComponents(components);
			addPreferredColorSources(perferredSources);
		}

		String getSourceProperty(int rgb) {
			return colorMapping.get(rgb);
		}

		String getSourceProperty(Font font) {
			return fontMapping.get(font);
		}

		void populateGroupMap(Map<String, PropertyGroup> groupMap) {
			for (String component : groupComponents) {
				groupMap.put(component, this);
			}
		}

		void addPreferredColorSources(String... preferedColorSources) {
			this.preferredPropertyColorSources.addAll(Arrays.asList(preferedColorSources));
		}

		void addComponents(String... properties) {
			groupComponents.addAll(Arrays.asList(properties));
		}

		void addFontMapping(Font font, String sourceId) {
			fontMapping.put(font, sourceId);
		}

		private Map<Integer, String> initialize(GThemeValueMap values) {
			colorMapping = new HashMap<>();
			ArrayList<String> reversed = new ArrayList<>(preferredPropertyColorSources);
			Collections.reverse(reversed);
			// go through in reverse order so that values at the top of the list have precedence
			// if multiple propertyBases have the save value.
			for (String propertyBase : reversed) {
				ColorValue colorValue = values.getColor(propertyBase);
				if (colorValue != null) {
					Color color = colorValue.get(values);
					colorMapping.put(color.getRGB(), propertyBase);
				}
			}
			return colorMapping;
		}
	}

}
