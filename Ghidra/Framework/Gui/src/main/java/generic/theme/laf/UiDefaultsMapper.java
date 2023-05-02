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
	public static final String LAF_COLOR_ID_PREFIX = "laf.color.";
	public static final String LAF_FONT_ID_PREFIX = "laf.font.";
	public static final String LAF_ICON_ID_PREFIX = "laf.icon.";
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
	private GThemeValueMap normalizedValues = new GThemeValueMap();

	private Map<String, String> lafIdToNormalizedIdMap = new HashMap<>();
	protected Set<String> ignoredLafIds = new HashSet<>();

	private Map<String, ColorMatcher> componentToColorMatcherMap = new HashMap<>();
	private Map<String, FontMatcher> componentToFontMatcherMap = new HashMap<>();

	// @formatter:off
	protected ColorMatcher viewColorMatcher = new ColorMatcher(BG_VIEW_ID,
							 								   FG_VIEW_ID,
							 								   BG_VIEW_SELECTED_ID,
							 								   FG_VIEW_SELECTED_ID);
	protected ColorMatcher tooltipColorMatcher = new ColorMatcher(BG_TOOLTIP_ID,
																  FG_TOOLTIP_ID);
	protected ColorMatcher defaultColorMatcher = new ColorMatcher(BG_CONTROL_ID,
							 									  FG_CONTROL_ID,
							 									  BG_VIEW_ID,
							 									  FG_VIEW_ID,
							 									  FG_DISABLED_ID,
							 									  BG_VIEW_SELECTED_ID,
							 									  FG_VIEW_SELECTED_ID,
							 									  BG_TOOLTIP_ID,
							 									  BG_BORDER_ID);

	protected FontMatcher menuFontMatcher = new FontMatcher(FONT_MENU_ID);
	protected FontMatcher viewFontMatcher = new FontMatcher(FONT_VIEW_ID);
	protected FontMatcher defaultFontMatcher = new FontMatcher(FONT_CONTROL_ID,
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

		assignSystemColorValues();
		assignSystemFontValues();

		registerIgnoredLafIds();

		assignColorMatchersToComponentIds();
		assignFontMatchersToComponentIds();

		assignNormalizedColorValues();
		assignNormalizedFontValues();
		assignNormalizedIconValues();
	}

	/**
	 * Returns the normalized id to value map that will be installed into the
	 * ApplicationThemeManager to be the user changeable values for affecting the Java
	 * LookAndFeel colors, fonts, and icons
	 * @return a map of changeable values that affect java LookAndFeel values
	 */
	public GThemeValueMap getJavaDefaults() {
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
		// values that are different than the defaults.
		//
		installGColorsIntoUIDefaults();
		installOverriddenFontsIntoUIDefaults(currentValues);
		installOverriddenIconsIntoUIDefaults(currentValues);
	}

	/**
	 * Returns a mapping of normalized LaF Ids so that when fonts and icons get changed using the
	 * normalized ids that are presented to the user, we know which LaF ids need to be updated in
	 * the UiDefaults so that the LookAndFeel will pick up and use the changes.
	 * @return a mapping of normalized LaF ids to original LaF ids.
	 */
	public Map<String, String> getNormalizedIdToLafIdMap() {
		Map<String, String> map = new HashMap<>();
		for (Entry<String, String> entry : lafIdToNormalizedIdMap.entrySet()) {
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
	protected void registerIgnoredLafIds() {

		ignoredLafIds.add("desktop");
		ignoredLafIds.add("activeCaption");
		ignoredLafIds.add("activeCaptionText");
		ignoredLafIds.add("activeCaptionBorder");
		ignoredLafIds.add("inactiveCaption");
		ignoredLafIds.add("inactiveCaptionText");
		ignoredLafIds.add("inactiveCaptionBorder");
		ignoredLafIds.add("window");
		ignoredLafIds.add("windowBorder");
		ignoredLafIds.add("windowText");
		ignoredLafIds.add("menu");
		ignoredLafIds.add("menuText");
		ignoredLafIds.add("text");
		ignoredLafIds.add("textText");
		ignoredLafIds.add("textHighlight");
		ignoredLafIds.add("textHighightText");
		ignoredLafIds.add("textInactiveText");
		ignoredLafIds.add("control");
		ignoredLafIds.add("controlText");
		ignoredLafIds.add("controlHighlight");
		ignoredLafIds.add("controlLtHighlight");
		ignoredLafIds.add("controlShadow");
		ignoredLafIds.add("controlDkShadow");
		ignoredLafIds.add("info");
		ignoredLafIds.add("infoText");
		ignoredLafIds.add("scrollbar");
	}

	/**
	 * Defines the values to assign to all the system color ids based on the best representative
	 * value defined in the {@link BasicLookAndFeel}
	 */
	protected void assignSystemColorValues() {
		// Originally, these values were assigned to the corresponding concepts as defined
		// in the BasicLookAndFeel such as "control", "text", etc. Unfortunately, those
		// conventions are rarely used by specific look and feels.  It was discovered that using a
		// representative component value worked much better. So each Look and Feel was examined and
		// those component values chosen here are the ones that seemed to work for the most look and
		// feels. If a specific look and feel needs different values, this class is designed to be
		// subclassed where the values can be overridden. See the NimbusUiDefaultsMapper as an
		// example.

		assignSystemColorFromLafId(BG_CONTROL_ID, "Button.background");
		assignSystemColorFromLafId(FG_CONTROL_ID, "Button.foreground");
		assignSystemColorFromLafId(BG_BORDER_ID, "InternalFrame.borderColor");

		assignSystemColorFromLafId(BG_VIEW_ID, "TextArea.background");
		assignSystemColorFromLafId(FG_VIEW_ID, "TextArea.foreground");
		assignSystemColorFromLafId(BG_VIEW_SELECTED_ID, "TextArea.selectionBackground");
		assignSystemColorFromLafId(FG_VIEW_SELECTED_ID, "TextArea.selectionForeground");

		assignSystemColorFromLafId(FG_DISABLED_ID, "Label.disabledForeground");

		assignSystemColorFromLafId(BG_TOOLTIP_ID, "ToolTip.background");
		assignSystemColorFromLafId(FG_TOOLTIP_ID, "ToolTip.foreground");

	}

	/**
	 * Assigns the system color id to a color value from the UiDefaults map.
	 * @param systemColorId the system color id to get a value for
	 * @param lafId the LaF key to use to retrieve a color from the UiDefaults
	 */
	protected void assignSystemColorFromLafId(String systemColorId, String lafId) {
		Color lafColor = defaults.getColor(lafId);
		if (lafColor == null) {
			Msg.debug(this, "Missing value for system color: \"" + systemColorId +
				"\". No value for laf id: \"" + lafId + "\".");
			return;
		}
		normalizedValues.addColor(new ColorValue(systemColorId, lafColor));
	}

	/**
	 * Assigns the system color id to a directly specified color and does not use the LaF to populate
	 * the system color.
	 * @param systemColorId the system color id to assign the given color
	 * @param color the color to be assigned to the system color id
	 */
	protected void assignSystemColorDirect(String systemColorId, Color color) {
		normalizedValues.addColor(new ColorValue(systemColorId, color));
	}

	/**
	 * Assigns the system font id a directly specified font and does not use the LaF to populate
	 * the system font.
	 * @param systemFontId the system font id to assign the given font
	 * @param font the font to be assigned to the system font id
	 */
	protected void assignSystemFontDirect(String systemFontId, Font font) {
		normalizedValues.addFont(new FontValue(systemFontId, font));
	}

	/**
	 * Defines the values to use for the system fonts.
	 */
	protected void assignSystemFontValues() {
		assignSystemFontFromLafId(FONT_CONTROL_ID, "Button.font");
		assignSystemFontFromLafId(FONT_VIEW_ID, "Table.font");
		assignSystemFontFromLafId(FONT_MENU_ID, "Menu.font");
	}

	private void assignSystemFontFromLafId(String systemFontId, String lafId) {

		Font lafFont = extractedValues.getResolvedFont(lafId);
		if (lafFont == null) {
			Msg.debug(this, "Missing value for system font: \"" + systemFontId +
				"\". No value for laf id: \"" + lafId + "\".");
			return;
		}
		normalizedValues.addFont(new FontValue(systemFontId, fromUiResource(lafFont)));
	}

	/**
	 * Assigns the appropriate font matcher to each component in the related component group
	 */
	protected void assignFontMatchersToComponentIds() {
		defineComponentFontMatcher(MENU_COMPONENTS, menuFontMatcher);
		defineComponentFontMatcher(VIEW_COMPONENTS, viewFontMatcher);
	}

	/**
	 * Assigns the appropriate color matcher to each component in the related component group
	 */
	protected void assignColorMatchersToComponentIds() {
		defineComponentColorMatcher(VIEW_COMPONENTS, viewColorMatcher);
		defineComponentColorMatcher(TOOLTIP_COMPONENTS, tooltipColorMatcher);
	}

	/**
	 * Assigns every component name in the component group to the given ColorValueMatcher
	 * @param componentGroups a list of component names
	 * @param matcher the ColorMatcher that will provide the precedence of system ids to
	 * search when replacing LaF component specific values
	 */
	private void defineComponentColorMatcher(String[] componentGroups, ColorMatcher matcher) {
		for (String componentGroup : componentGroups) {
			componentToColorMatcherMap.put(componentGroup, matcher);
		}
	}

	/**
	 * Assigns every component name in a component group to the given FontValueMapper
	 * @param componentGroups a list of component names
	 * @param matcher the FontValueMatcher that will provide the precedence of ststem font ids to
	 * search when replacing LaF component specific fonts with a system Font
	 */
	private void defineComponentFontMatcher(String[] componentGroups, FontMatcher matcher) {
		for (String componentGroup : componentGroups) {
			componentToFontMatcherMap.put(componentGroup, matcher);
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
			if (ignoredLafIds.contains(lafId)) {
				continue;
			}

			String createdId = LAF_FONT_ID_PREFIX + lafId;
			lafIdToNormalizedIdMap.put(lafId, createdId);

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
				lafIdToNormalizedIdMap.put(lafId, createdId);
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
			if (ignoredLafIds.contains(lafId)) {
				continue;
			}
			String createdId = LAF_COLOR_ID_PREFIX + lafId;
			lafIdToNormalizedIdMap.put(lafId, createdId);

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
		ColorMatcher colorMatcher = componentToColorMatcherMap.get(componentName);
		// check in widget specific group first
		if (colorMatcher != null) {
			String systemId = colorMatcher.getSystemId(lafColor);
			if (systemId != null) {
				return systemId;
			}
		}
		// not found in widget specific group, check general component groups
		return defaultColorMatcher.getSystemId(lafColor);
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
		FontMatcher fontMatcher = componentToFontMatcherMap.get(componentName);
		// check in widget specific group first
		if (fontMatcher != null) {
			String systemId = fontMatcher.getSystemId(lafFont);
			if (systemId != null) {
				return systemId;
			}
		}
		// not found in widget specific group, check general component groups
		return defaultFontMatcher.getSystemId(lafFont);
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
			String standardColorId = lafIdToNormalizedIdMap.get(lafId);
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
			String standardId = lafIdToNormalizedIdMap.get(lafId);
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
			String standardId = lafIdToNormalizedIdMap.get(lafId);
			Font overriddenFont = currentValues.getResolvedFont(standardId);
			if (overriddenFont != null && overriddenFont != currentFont) {
				defaults.put(lafId, new FontUIResource(overriddenFont));
			}
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
		String normalizedId = lafIdToNormalizedIdMap.get(lafId);
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
		List<String> colorKeys = new ArrayList<>();
		List<Object> keyList = IteratorUtils.toList(defaults.keys().asIterator());
		for (Object key : keyList) {
			if (key instanceof String) {
				Object value = defaults.get(key);
				if (clazz.isInstance(value)) {
					colorKeys.add((String) key);
				}
			}
		}
		return colorKeys;
	}

	/**
	 * Used to match values (Colors or Fonts) into appropriate system ids. System ids are searched
	 * in the order the system ids are given in the constructor.
	 * @param <T> The theme value type (Color or Font)
	 */
	private abstract class ValueMatcher<T> {
		private Map<T, String> map = new HashMap<>();
		private List<String> systemIdList;
		private boolean initialized;

		ValueMatcher(String... systemIds) {
			systemIdList = new ArrayList<>(Arrays.asList(systemIds));
		}

		private void initialize() {
			initialized = true;

			// process in reverse order so that earlier items in the list can overwrite later
			// items if they have the same font
			for (int i = systemIdList.size() - 1; i >= 0; i--) {
				String systemId = systemIdList.get(i);
				T value = getValueFromJavaDefaults(systemId);
				if (value != null) {
					map.put(value, systemId);
				}
			}
		}

		protected abstract T getValueFromJavaDefaults(String systemId);

		String getSystemId(T value) {
			if (!initialized) {
				initialize();
			}
			return map.get(value);
		}
	}

	/**
	 * Searches through all the system color ids registered for this matcher to find a system color
	 * id that matches a given color. The order that color system ids are added is important and is
	 * the precedence order if more than one system color id has the same color.
	 */
	private class ColorMatcher extends ValueMatcher<Color> {

		ColorMatcher(String... systemIds) {
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
	private class FontMatcher extends ValueMatcher<Font> {
		FontMatcher(String... systemIds) {
			super(systemIds);
		}

		@Override
		protected Font getValueFromJavaDefaults(String systemId) {
			return normalizedValues.getResolvedFont(systemId);
		}
	}
}
