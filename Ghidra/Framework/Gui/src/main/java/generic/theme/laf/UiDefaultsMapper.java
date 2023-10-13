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

import static generic.theme.SystemThemeIds.*;

import java.awt.Color;
import java.awt.Font;
import java.util.*;
import java.util.Map.Entry;

import javax.swing.*;
import javax.swing.plaf.FontUIResource;
import javax.swing.plaf.UIResource;
import javax.swing.plaf.basic.BasicLookAndFeel;

import org.apache.commons.collections4.IteratorUtils;

import generic.theme.*;
import ghidra.util.Msg;

/**
 * The purpose of this class is to introduce multiple levels of indirection into the Java
 * {@code LookAndFeel} (LaF), which allows the user to change these values.  Further, when
 * introducing this indirection we combine the Java settings into user-friendly system ids to make
 * changing these values easier.
 * <P>
 * This class defines these user-friendly groups.  The default system assignments are based on the
 * {@link BasicLookAndFeel} values.
 * <P>
 * Subclasses can override the mapping of these standard system values for particular LaFs that have
 * different ids or color assignments.
 * <P>
 * Some basic concepts:
 *  <UL>
 *  	<LI>UI Defaults - key-value pairs defined by the Java LaF; there are 2 key types, widget
 *                        keys and Java group/reusable keys (e.g., Button.background; control)
 *      <LI>UI Indirection - UI Defaults values are changed to point to custom terms we created to
 *                        allow for indirection (e.g., Button.background -> laf.color.Button.background)
 *      <LI>Normalized Keys - keys we created to facilitate the UI Indirection, based upon the Java
 *                        keys (e.g., laf.color.Button.background)
 *  	<LI>System Color/Font Keys - user facing terms for common color or font concepts into an
 *  					easy-to-change setting (e.g., system.color.fg.text)
 *      <LI>Palette Keys - dynamically generated color palette keys based on the LaF for any colors
 *      				  and fonts that were not mapped into an system color or font (e.g.,
 *      				  laf.palette.color.01)
 *  </UL>
 *
 * <P>
 *  The mapper performs the following operations:
 *  <OL>
 * <LI>Extracts all color, font, and icon values from the UI Defaults.</LI>
 * <LI>Use the current LaF values to populate the pre-defined system colors and fonts.</LI>
 * <LI>Any UI Defaults values not assigned in the previous step will be assigned to a dynamic shared
 *     palette color or font.
 * <LI>Update Java UI Defaults to use our indirection and system values.</LI>
 * </OL>
 *
 */
public class UiDefaultsMapper {

	public static final String LAF_COLOR_ID_PREFIX = ColorValue.LAF_ID_PREFIX;
	public static final String LAF_FONT_ID_PREFIX = FontValue.LAF_ID_PREFIX;
	public static final String LAF_ICON_ID_PREFIX = IconValue.LAF_ID_PREFIX;

	/** A prefix for UIManager properties that are not colors, fonts or icons (e.g., boolean) */
	public static final String LAF_PROPERTY_PREFIX = "laf.property.";
	private static final String LAF_COLOR_PALETTE_PREFIX = "laf.palette.color.";
	private static final String LAF_FONT_PALETTE_PREFIX = "laf.palette.font.";

	private static final String[] MENU_COMPONENTS =
		{ "Menu", "MenuBar", "MenuItem", "PopupMenu", "RadioButtonMenuItem", "CheckBoxMenuItem" };
	private static final String[] VIEW_COMPONENTS =
		{ "FileChooser", "ColorChooser", "ComboBox", "List", "Table", "Tree", "TextField",
			"FormattedTextField", "PasswordField", "TextArea", "TextPane", "EditorPane" };
	private static final String[] TOOLTIP_COMPONENTS = { "ToolTip" };

	protected UIDefaults defaults;
	private GThemeValueMap extractedValues;

	/** 'normalized' values have keys that start with 'laf.' */
	private GThemeValueMap normalizedValues = new GThemeValueMap();

	/** Maps Look and Feel keys to standardized keys that start with 'laf.' */
	private Map<String, String> javaIdToNormalizedId = new HashMap<>();
	protected Set<String> ignoredJavaIds = new HashSet<>();

	private Map<String, ColorGrouper> componentToColorGrouper = new HashMap<>();
	private Map<String, FontGrouper> componentToFontGrouper = new HashMap<>();

	// @formatter:off
	protected ColorGrouper viewColorGrouper = new ColorGrouper(BG_VIEW_ID,
							 								   FG_VIEW_ID,
							 								   BG_VIEW_SELECTED_ID,
							 								   FG_VIEW_SELECTED_ID);
	protected ColorGrouper tooltipColorGrouper = new ColorGrouper(BG_TOOLTIP_ID,
																  FG_TOOLTIP_ID);
	protected ColorGrouper defaultColorMatcher = new ColorGrouper(BG_CONTROL_ID,
							 									  FG_CONTROL_ID,
							 									  BG_VIEW_ID,
							 									  FG_VIEW_ID,
							 									  FG_DISABLED_ID,
							 									  BG_VIEW_SELECTED_ID,
							 									  FG_VIEW_SELECTED_ID,
							 									  BG_TOOLTIP_ID,
							 									  BG_BORDER_ID);

	protected FontGrouper menuFontGrouper = new FontGrouper(FONT_MENU_ID);
	protected FontGrouper viewFontGrouper = new FontGrouper(FONT_VIEW_ID);
	protected FontGrouper defaultFontMatcher = new FontGrouper(FONT_CONTROL_ID,
															   FONT_VIEW_ID,
															   FONT_MENU_ID);

	//@formatter:on

	private Map<Color, String> lafColorPaletteMap = new HashMap<>();
	private Map<Font, String> lafFontPaletteMap = new HashMap<>();
	private int nextColorPaletteId;
	private int nextFontPaletteId;

	protected UiDefaultsMapper(UIDefaults defaults) {
		this.defaults = defaults;
		this.extractedValues = extractColorFontAndIconValuesFromDefaults();

		pickRepresentativeValueForColorGroups();
		pickRepresentativeValueForFontGroups();

		registerIgnoredJavaIds();

		buildComponentToColorGrouperMap();
		buildComponentToFontGrouperMap();

		assignNormalizedColorValues();
		assignNormalizedFontValues();
		assignNormalizedIconValues();
	}

	/**
	 * Returns the normalized id to value map that will be installed into the theme manager to be
	 * the user changeable values for affecting the Java LookAndFeel colors, fonts, and icons.
	 * <p>
	 * The keys in the returned map have been normalized and all start with 'laf.'
	 * 
	 * 
	 * @return a map of changeable values that affect java LookAndFeel values
	 */
	public GThemeValueMap getNormalizedJavaDefaults() {
		return normalizedValues;
	}

	/**
	 * Updates the UIDefaults file with indirect colors (GColors) and any overridden font or icon
	 * values as defined in theme.properites files and saved themes.
	 * @param currentValues a Map that contains all the values including those the may have
	 * been overridden by the theme.properties files or saved themes
	 */
	public void installValuesIntoUIDefaults(GThemeValueMap currentValues) {
		//
		// In the UI Defaults, colors use indirect values and fonts and icons use direct values.
		// Here we install our GColors for the indirect colors.  Then we set any font and icon
		// values that are different than the defaults.  Finally, we apply any overridden Java
		// properties.
		//
		installGColorsIntoUIDefaults();
		installOverriddenFontsIntoUIDefaults(currentValues);
		installOverriddenIconsIntoUIDefaults(currentValues);
		installOverriddenPropertiesIntoUIDefaults(currentValues);
	}

	/**
	 * Returns a mapping of normalized LaF Ids so that when fonts and icons get changed using the
	 * normalized ids that are presented to the user, we know which LaF ids need to be updated in
	 * the UiDefaults so that the LookAndFeel will pick up and use the changes.
	 * 
	 * @return a mapping of normalized LaF ids to original LaF ids.
	 */
	public Map<String, String> getNormalizedIdToLafIdMap() {
		Map<String, String> map = new HashMap<>();
		for (Entry<String, String> entry : javaIdToNormalizedId.entrySet()) {
			String lafId = entry.getKey();
			String standardId = entry.getValue();
			map.put(standardId, lafId);
		}
		return map;
	}

	/**
	 * Registers any {@link LookAndFeel} ids that are not used directly (e.g. "control", "text",
	 * etc.) so that these values won't get mapped to any normalized id. There is no need for these
	 * values to show up in the theme values, since changing them will have no effect. They are
	 * used to seed the values for the system color and fonts. Subclasses should
	 * override this method to add additional ids so they won't show up in the theme values.
	 */
	protected void registerIgnoredJavaIds() {

		ignoredJavaIds.add("desktop");
		ignoredJavaIds.add("activeCaption");
		ignoredJavaIds.add("activeCaptionText");
		ignoredJavaIds.add("activeCaptionBorder");
		ignoredJavaIds.add("inactiveCaption");
		ignoredJavaIds.add("inactiveCaptionText");
		ignoredJavaIds.add("inactiveCaptionBorder");
		ignoredJavaIds.add("window");
		ignoredJavaIds.add("windowBorder");
		ignoredJavaIds.add("windowText");
		ignoredJavaIds.add("menu");
		ignoredJavaIds.add("menuText");
		ignoredJavaIds.add("text");
		ignoredJavaIds.add("textText");
		ignoredJavaIds.add("textHighlight");
		ignoredJavaIds.add("textHighightText");
		ignoredJavaIds.add("textInactiveText");
		ignoredJavaIds.add("control");
		ignoredJavaIds.add("controlText");
		ignoredJavaIds.add("controlHighlight");
		ignoredJavaIds.add("controlLtHighlight");
		ignoredJavaIds.add("controlShadow");
		ignoredJavaIds.add("controlDkShadow");
		ignoredJavaIds.add("info");
		ignoredJavaIds.add("infoText");
		ignoredJavaIds.add("scrollbar");
	}

	/**
	 * Defines the values to assign to all the system color ids based on the best representative
	 * value defined in the {@link BasicLookAndFeel}
	 */
	protected void pickRepresentativeValueForColorGroups() {
		// Originally, these values were assigned to the corresponding concepts as defined
		// in the BasicLookAndFeel such as "control", "text", etc. Unfortunately, those
		// conventions are rarely used by specific look and feels.  It was discovered that using a
		// representative component value worked much better. So each Look and Feel was examined and
		// those component values chosen here are the ones that seemed to work for the most look and
		// feels. If a specific look and feel needs different values, this class is designed to be
		// subclassed where the values can be overridden. See the NimbusUiDefaultsMapper as an
		// example.

		setGroupColorUsingJavaRepresentative(BG_CONTROL_ID, "Button.background");
		setGroupColorUsingJavaRepresentative(FG_CONTROL_ID, "Button.foreground");
		setGroupColorUsingJavaRepresentative(BG_BORDER_ID, "InternalFrame.borderColor");

		setGroupColorUsingJavaRepresentative(BG_VIEW_ID, "TextArea.background");
		setGroupColorUsingJavaRepresentative(FG_VIEW_ID, "TextArea.foreground");
		setGroupColorUsingJavaRepresentative(BG_VIEW_SELECTED_ID, "TextArea.selectionBackground");
		setGroupColorUsingJavaRepresentative(FG_VIEW_SELECTED_ID, "TextArea.selectionForeground");

		setGroupColorUsingJavaRepresentative(FG_DISABLED_ID, "Label.disabledForeground");

		setGroupColorUsingJavaRepresentative(BG_TOOLTIP_ID, "ToolTip.background");
		setGroupColorUsingJavaRepresentative(FG_TOOLTIP_ID, "ToolTip.foreground");

	}

	/**
	 * Assigns the system color id to a color value from the UiDefaults map.
	 * @param group the system color id to get a value for
	 * @param javaId the LaF key to use to retrieve a color from the UiDefaults
	 */
	protected void setGroupColorUsingJavaRepresentative(String group, String javaId) {
		Color javaColor = defaults.getColor(javaId);
		if (javaColor == null) {
			Msg.debug(this, "Missing value for system color: \"" + group +
				"\". No value for java id: \"" + javaId + "\".");
			return;
		}
		normalizedValues.addColor(new ColorValue(group, javaColor));
	}

	/**
	 * This allows clients to hard-code a chosen color for a group
	 * 
	 * @param group the system color id to assign the given color
	 * @param color the color to be assigned to the system color id
	 */
	protected void setGroupColor(String group, Color color) {
		normalizedValues.addColor(new ColorValue(group, color));
	}

	/**
	 * This allows clients to hard-code a chosen font for a group
	 * 
	 * @param group the system font id to assign the given font
	 * @param font the font to be assigned to the system font id
	 */
	protected void setGroupFont(String group, Font font) {
		normalizedValues.addFont(new FontValue(group, font));
	}

	protected void setComponentFont(String componentName, Font font) {
		normalizedValues.addFont(new FontValue(componentName, font));
	}

	/**
	 * Defines the font values to use for each group based upon a chosen Java representative.
	 */
	protected void pickRepresentativeValueForFontGroups() {
		setGroupFontUsingRepresentative(FONT_CONTROL_ID, "Button.font");
		setGroupFontUsingRepresentative(FONT_VIEW_ID, "Table.font");
		setGroupFontUsingRepresentative(FONT_MENU_ID, "Menu.font");
	}

	private void setGroupFontUsingRepresentative(String fontGroup, String javaId) {

		Font representativeFont = extractedValues.getResolvedFont(javaId);
		if (representativeFont == null) {
			Msg.debug(this, "Missing value for system font: \"" + fontGroup +
				"\". No value for java id: \"" + javaId + "\".");
			return;
		}
		normalizedValues.addFont(new FontValue(fontGroup, fromUiResource(representativeFont)));
	}

	/**
	 * Sets the font grouper for each component group
	 */
	protected void buildComponentToFontGrouperMap() {
		mapComponentsToFontGrouper(menuFontGrouper, MENU_COMPONENTS);
		mapComponentsToFontGrouper(viewFontGrouper, VIEW_COMPONENTS);
	}

	/**
	 * Sets the color grouper for each component group
	 */
	protected void buildComponentToColorGrouperMap() {
		mapComponentsToColorGrouper(viewColorGrouper, VIEW_COMPONENTS);
		mapComponentsToColorGrouper(tooltipColorGrouper, TOOLTIP_COMPONENTS);
	}

	/**
	 * Assigns every component name in the component group to the given ColorValueMatcher
	 * @param grouper the ColorMatcher that will provide the precedence of system ids to
	 * search when replacing LaF component specific values
	 * @param componentGroup a list of component names
	 */
	private void mapComponentsToColorGrouper(ColorGrouper grouper, String... componentGroup) {
		for (String name : componentGroup) {
			componentToColorGrouper.put(name, grouper);
		}
	}

	/**
	 * Assigns every component name in a component group to the given FontValueMapper
	 * @param grouper the FontValueMatcher that will provide the precedence of system font ids to
	 * search when replacing LaF component specific fonts with a system Font
	 * @param componentGroup a list of component names
	 */
	private void mapComponentsToFontGrouper(FontGrouper grouper, String... componentGroup) {
		for (String name : componentGroup) {
			componentToFontGrouper.put(name, grouper);
		}
	}

	/**
	 * Populates the GThemeValueMap with normalized font ids. For example
	 * it will assign "laf.font.Button.font" to "system.font.control".
	 */
	private void assignNormalizedFontValues() {
		List<String> list = new ArrayList<>(extractedValues.getFontIds());
		Collections.sort(list);
		for (String lafId : list) {
			// we don't want to create java defaults for laf system ids since changing them would
			// have no effect
			if (ignoredJavaIds.contains(lafId)) {
				continue;
			}

			String createdId = LAF_FONT_ID_PREFIX + lafId;
			javaIdToNormalizedId.put(lafId, createdId);

			Font lafFont = extractedValues.getResolvedFont(lafId);
			FontValue fontValue = getFontValue(createdId, lafId, lafFont);
			normalizedValues.addFont(fontValue);
		}
	}

	/**
	 * Populates the GThemeValueMap with normalized icon ids. For example
	 * it will assign "laf.font.CheckBox.icon" to a direct icon that was mined from the UiDefaults
	 * using the id "CheckBox.icon"
	 */
	private void assignNormalizedIconValues() {
		for (String lafId : extractedValues.getIconIds()) {
			String createdId = LAF_ICON_ID_PREFIX + lafId;
			Icon icon = extractedValues.getResolvedIcon(lafId);
			if (icon != null) {
				normalizedValues.addIcon(new IconValue(createdId, icon));
				javaIdToNormalizedId.put(lafId, createdId);
			}
		}
	}

	/**
	 * Populates the GThemeValueMap with normalized color ids. For example
	 * it will assign "laf.color.Button.background" to "system.color.bg.control".
	 */
	protected void assignNormalizedColorValues() {
		List<String> list = new ArrayList<>(extractedValues.getColorIds());
		Collections.sort(list);
		for (String lafId : list) {
			if (ignoredJavaIds.contains(lafId)) {
				continue;
			}
			String createdId = LAF_COLOR_ID_PREFIX + lafId;
			javaIdToNormalizedId.put(lafId, createdId);

			Color lafColor = extractedValues.getResolvedColor(lafId);
			ColorValue colorValue = getColorValue(createdId, lafId, lafColor);
			normalizedValues.addColor(colorValue);
		}
	}

	/**
	 * Creates a {@link ColorValue} for the given id. It either finds a system color id that matches
	 * the given color, or a shared palette color if no system color found.
	 * @param id the id to get a color value for
	 * @param lafId the lafId that we are creating a standard id/color value for
	 * @param lafColor the color as defined in the UiDefaults for the lafId
	 * @return a {@link ColorValue} for the given id. It either finds a system color id that matches
	 * the given color, or a shared palette color if no system color found.
	 */
	private ColorValue getColorValue(String id, String lafId, Color lafColor) {
		String systemId = findSystemColorId(lafId, lafColor);

		if (systemId == null) {
			systemId = getColorPaletteId(lafColor);
		}

		return new ColorValue(id, systemId);
	}

	/**
	 * Creates a {@link FontValue} for the given id. It either finds a system font id that matches
	 * the given Font, or a shared palette Font if no system font found.
	 * @param id the id to get a Font value for
	 * @param lafId the lafId that we are creating a standard id/Font value for
	 * @param lafFont the Font as defined in the UiDefaults for the lafId
	 * @return a {@link FontValue} for the given id. It either finds a system font id that matches
	 * the given Font, or a shared palette Font if no group Font found.
	 */
	private FontValue getFontValue(String id, String lafId, Font lafFont) {
		String systemFontId = findSystemFontId(lafId, lafFont);
		if (systemFontId == null) {
			systemFontId = getFontPaletteId(lafFont);
		}
		return new FontValue(id, systemFontId);
	}

	/**
	 * Finds a matching color palette id or creates a new one
	 * @param lafColor the color to find a matching palette color for
	 * @return  a matching color palette id or creates a new one
	 */
	private String getColorPaletteId(Color lafColor) {
		String paletteId = lafColorPaletteMap.get(lafColor);
		if (paletteId == null) {
			nextColorPaletteId++;
			// laf.palette.color01
			paletteId = String.format("%s%02d", LAF_COLOR_PALETTE_PREFIX, nextColorPaletteId);
			lafColorPaletteMap.put(lafColor, paletteId);
			normalizedValues.addColor(new ColorValue(paletteId, lafColor));
		}
		return paletteId;
	}

	/**
	 * Finds a matching font palette id or creates a new one
	 * @param lafFont the font to find a matching palette font for
	 * @return  a matching font palette id or creates a new one
	 */
	private String getFontPaletteId(Font lafFont) {
		String paletteId = lafFontPaletteMap.get(lafFont);
		if (paletteId == null) {
			nextFontPaletteId++;

			// laf.palette.font01
			paletteId = String.format("%s%02d", LAF_FONT_PALETTE_PREFIX, nextFontPaletteId);
			lafFontPaletteMap.put(lafFont, paletteId);
			normalizedValues.addFont(new FontValue(paletteId, lafFont));
		}
		return paletteId;
	}

	/**
	 * Attempts to find a system color id that matches the given color. The order system ids are
	 * searched depends on the component (Button, Menu, etc.) which is derived from the given
	 * lafId.
	 * @param lafId the lafId we are attempting to get a system color for
	 * @param lafColor the color we are trying to match to a system color
	 * @return a system color id that matches the given lafColor or null if one can't be found
	 */
	private String findSystemColorId(String lafId, Color lafColor) {
		String componentName = getComponentName(lafId);
		ColorGrouper colorMatcher = componentToColorGrouper.get(componentName);
		// check in widget specific group first
		if (colorMatcher != null) {
			String systemId = colorMatcher.getGroupId(lafColor);
			if (systemId != null) {
				return systemId;
			}
		}
		// not found in widget specific group, check general component groups
		return defaultColorMatcher.getGroupId(lafColor);
	}

	/**
	 * Attempts to find a system font id that matches the given font. The order system fonts are
	 * searched depends on the component (Button, Menu, etc.) which is derived from the given
	 * lafId.
	 * @param lafId the lafId we are attempting to get a system font for
	 * @param lafFont the font we are trying to match to a system font
	 * @return a system font id that matches the given lafFont or null if one can't be found
	 */
	private String findSystemFontId(String lafId, Font lafFont) {
		String componentName = getComponentName(lafId);
		FontGrouper fontMatcher = componentToFontGrouper.get(componentName);
		// check in widget specific group first
		if (fontMatcher != null) {
			String systemId = fontMatcher.getGroupId(lafFont);
			if (systemId != null) {
				return systemId;
			}
		}
		// not found in widget specific group, check general component groups
		return defaultFontMatcher.getGroupId(lafFont);
	}

	/**
	 * Gets the component name from the given lafId.
	 * @param lafId the lafId that starts with a component name
	 * @return  the component name from the given lafId.
	 */
	private String getComponentName(String lafId) {
		int dotIndex = lafId.indexOf(".");
		if (dotIndex < 0) {
			return lafId;
		}
		return lafId.substring(0, dotIndex);
	}

	/**
	 * Replaces UiDefaults values with {@link GColorUIResource} values the provide the theme
	 * indirection.
	 */
	protected void installGColorsIntoUIDefaults() {
		Map<String, GColorUIResource> cachedColors = new HashMap<>();

		for (String lafId : extractedValues.getColorIds()) {
			String standardColorId = javaIdToNormalizedId.get(lafId);
			if (standardColorId != null) {
				GColorUIResource sharedGColor = getSharedGColor(cachedColors, standardColorId);
				defaults.put(lafId, sharedGColor);
			}
		}
	}

	/**
	 * Replace UiDefault values with theme overridden values.
	 * @param currentValues the theme values that potentially override a laf icon value
	 */
	private void installOverriddenIconsIntoUIDefaults(GThemeValueMap currentValues) {
		for (String lafId : extractedValues.getIconIds()) {
			Icon currentIcon = extractedValues.getResolvedIcon(lafId);
			String standardId = javaIdToNormalizedId.get(lafId);
			Icon overriddenIcon = currentValues.getResolvedIcon(standardId);
			if (overriddenIcon != null && currentIcon != overriddenIcon) {
				defaults.put(lafId, overriddenIcon);
			}
		}

	}

	/**
	 * Replaces any theme overridden fonts into the UiDefaults.
	 * @param currentValues the theme values that potentially override a laf font value
	 */
	private void installOverriddenFontsIntoUIDefaults(GThemeValueMap currentValues) {
		for (String lafId : extractedValues.getFontIds()) {
			Font currentFont = extractedValues.getResolvedFont(lafId);
			String standardId = javaIdToNormalizedId.get(lafId);
			Font overriddenFont = currentValues.getResolvedFont(standardId);
			if (overriddenFont != null && overriddenFont != currentFont) {
				defaults.put(lafId, new FontUIResource(overriddenFont));
			}
		}
	}

	/**
	 * Updates all non- (color/font/icon) UIManager properties.  These properties are UIManager
	 * properties that the user has overridden in the {@code theme.properties} files.  These
	 * properties may use any type of value that is not a color/font/icon.
	 * @param currentValues the theme values that potentially override a laf font value
	 */
	private void installOverriddenPropertiesIntoUIDefaults(GThemeValueMap currentValues) {
		for (JavaPropertyValue property : currentValues.getProperties()) {
			defaults.put(property.getId(), property.get(currentValues));
		}
	}

	/**
	 * When putting {@link GColorUIResource} values into the UiDefaults, we need to make sure
	 * we use the same instance for the same color. Some LookAndFeels do "==" checks on colors
	 * when updating UI values.
	 * @param cache the cache of shared {@link GColorUIResource}s
	 * @param id the id we are creating a shared GColorUIResource for
	 * @return a GColorUIResource such that only one instance for a given id exists.
	 */
	private GColorUIResource getSharedGColor(Map<String, GColorUIResource> cache, String id) {
		GColorUIResource gColor = cache.get(id);
		if (gColor == null) {
			gColor = new GColorUIResource(id);
			cache.put(id, gColor);
		}
		return gColor;
	}

	protected void overrideColor(String lafId, String sytemId) {
		String normalizedId = javaIdToNormalizedId.get(lafId);
		if (normalizedId == null) {
			Msg.debug(this, "Missing value for laf id: \"" + lafId);
			return;
		}
		normalizedValues.addColor(new ColorValue(normalizedId, sytemId));
	}

	/**
	 * Mines the UiDefaults for all color values.
	 * @return a map of id to values for UIDefaults Colors.
	 */
	protected GThemeValueMap extractColorFontAndIconValuesFromDefaults() {
		GThemeValueMap values = new GThemeValueMap();

		List<String> ids = getLookAndFeelIdsForType(Color.class);
		for (String id : ids) {
			values.addColor(new ColorValue(id, defaults.getColor(id)));
		}

		ids = getLookAndFeelIdsForType(Font.class);
		for (String id : ids) {
			values.addFont(new FontValue(id, defaults.getFont(id)));
		}

		ids = getLookAndFeelIdsForType(Icon.class);
		for (String id : ids) {
			Icon icon = defaults.getIcon(id);
			values.addIcon(new IconValue(id, icon));
		}
		return values;
	}

	private Font fromUiResource(Font font) {
		if (font instanceof UIResource) {
			return new FontNonUiResource(font);
		}
		return font;
	}

	/**
	 * Finds all ids in the UIDefaults for a specific type (Color, Font, Icon)
	 * @param clazz the class of the type to mine for
	 * @return a list of all ids that have the given value type
	 */
	private List<String> getLookAndFeelIdsForType(Class<?> clazz) {
		List<String> ids = new ArrayList<>();
		List<Object> keyList = IteratorUtils.toList(defaults.keys().asIterator());
		for (Object key : keyList) {
			if (key instanceof String) {
				Object value = defaults.get(key);
				if (clazz.isInstance(value)) {
					ids.add((String) key);
				}
			}
		}
		return ids;
	}

	/**
	 * Used to match values (Colors or Fonts) into appropriate system groups. System group are
	 * searched in the order the groups are given in the constructor.
	 * <p>
	 * Groups allow us to use the same group id for many components that by default have the same
	 * value (Color or Font).  This grouper allows us to specify the precedence to use when
	 * searching for the best group.
	 * 
	 * @param <T> The theme value type (Color or Font)
	 */
	private abstract class ValueGrouper<T> {
		private Map<T, String> idsByFont = new HashMap<>();
		private List<String> groupIds;
		private boolean initialized;

		ValueGrouper(String... ids) {
			groupIds = new ArrayList<>(Arrays.asList(ids));
		}

		private void initialize() {
			initialized = true;

			// process in reverse order so that earlier items in the list can overwrite later
			// items if they have the same value
			for (int i = groupIds.size() - 1; i >= 0; i--) {
				String groupId = groupIds.get(i);
				T value = getValueFromJavaDefaults(groupId);
				if (value != null) {
					idsByFont.put(value, groupId);
				}
			}
		}

		protected abstract T getValueFromJavaDefaults(String systemId);

		String getGroupId(T value) {
			if (!initialized) {
				initialize();
			}
			return idsByFont.get(value);
		}
	}

	/**
	 * Searches through all the system color ids registered for this matcher to find a system color
	 * id that matches a given color. The order that color system ids are added is important and is
	 * the precedence order if more than one system color id has the same color.
	 */
	private class ColorGrouper extends ValueGrouper<Color> {

		ColorGrouper(String... systemIds) {
			super(systemIds);
		}

		@Override
		protected Color getValueFromJavaDefaults(String systemId) {
			return normalizedValues.getResolvedColor(systemId);
		}

	}

	/**
	 * Searches through all the system font ids registered for this matcher to find a system font id
	 * that matches a given font. The order that system font ids are added is important and is
	 * the precedence order if more than one system id has the same font.
	 */
	private class FontGrouper extends ValueGrouper<Font> {
		FontGrouper(String... systemIds) {
			super(systemIds);
		}

		@Override
		protected Font getValueFromJavaDefaults(String systemId) {
			return normalizedValues.getResolvedFont(systemId);
		}
	}
}
