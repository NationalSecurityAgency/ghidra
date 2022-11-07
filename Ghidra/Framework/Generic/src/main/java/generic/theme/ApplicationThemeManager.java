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

import java.awt.Component;
import java.io.File;
import java.util.*;

import javax.swing.*;
import javax.swing.plaf.ComponentUI;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLightLaf;

import generic.theme.laf.LookAndFeelManager;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;

/**
 * This is the fully functional {@link ThemeManager} that manages themes in a application. To
 * activate the theme functionality, Applications (or tests) must call 
 * {@link ApplicationThemeManager#initialize()}
 */
public class ApplicationThemeManager extends ThemeManager {
	private GTheme activeTheme = getDefaultTheme();
	private Set<GTheme> allThemes = null;

	private GThemeValueMap applicationDefaults = new GThemeValueMap();
	private GThemeValueMap applicationDarkDefaults = new GThemeValueMap();
	private GThemeValueMap javaDefaults = new GThemeValueMap();
	private GThemeValueMap systemValues = new GThemeValueMap();

	protected ThemeFileLoader themeFileLoader = new ThemeFileLoader();
	protected ThemePreferences themePreferences = new ThemePreferences();

	private Map<String, GColorUIResource> gColorMap = new HashMap<>();
	private Map<String, GIconUIResource> gIconMap = new HashMap<>();

	// stores the original value for ids whose value has changed from the current theme
	private GThemeValueMap changedValuesMap = new GThemeValueMap();
	protected LookAndFeelManager lookAndFeelManager;

	/**
	 * Initialized the Theme and its values for the application.
	 */
	public static void initialize() {
		if (INSTANCE instanceof ApplicationThemeManager) {
			Msg.error(ThemeManager.class, "Attempted to initialize theming more than once!");
			return;
		}

		ApplicationThemeManager themeManager = new ApplicationThemeManager();
		themeManager.doInitialize();
	}

	protected ApplicationThemeManager() {
		// AppliationThemeManagers always replace any other instances
		INSTANCE = this;
		installInGui();
	}

	protected void doInitialize() {
		installFlatLookAndFeels();
		loadThemeDefaults();
		setTheme(themePreferences.load());
	}

	@Override
	public void reloadApplicationDefaults() {
		loadThemeDefaults();
		buildCurrentValues();
		lookAndFeelManager.resetAll(javaDefaults);
		notifyThemeChanged(new AllValuesChangedThemeEvent(false));
	}

	@Override
	public void restoreThemeValues() {
		buildCurrentValues();
		lookAndFeelManager.resetAll(javaDefaults);
		notifyThemeChanged(new AllValuesChangedThemeEvent(false));
	}

	@Override
	public void restoreColor(String id) {
		if (changedValuesMap.containsColor(id)) {
			setColor(changedValuesMap.getColor(id));
		}
	}

	@Override
	public void restoreFont(String id) {
		if (changedValuesMap.containsFont(id)) {
			setFont(changedValuesMap.getFont(id));
		}
	}

	@Override
	public void restoreIcon(String id) {
		if (changedValuesMap.containsIcon(id)) {
			setIcon(changedValuesMap.getIcon(id));
		}
	}

	@Override
	public boolean isChangedColor(String id) {
		return changedValuesMap.containsColor(id);
	}

	@Override
	public boolean isChangedFont(String id) {
		return changedValuesMap.containsFont(id);
	}

	@Override
	public boolean isChangedIcon(String id) {
		return changedValuesMap.containsIcon(id);
	}

	@Override
	public void setTheme(GTheme theme) {
		if (theme.hasSupportedLookAndFeel()) {
			activeTheme = theme;
			LafType lafType = theme.getLookAndFeelType();
			lookAndFeelManager = lafType.getLookAndFeelManager(this);
			try {
				lookAndFeelManager.installLookAndFeel();
				themePreferences.save(theme);
				notifyThemeChanged(new AllValuesChangedThemeEvent(true));
			}
			catch (Exception e) {
				Msg.error(this, "Error setting LookAndFeel: " + lafType.getName(), e);
			}
		}
		currentValues.checkForUnresolvedReferences();
	}

	@Override
	public void addTheme(GTheme newTheme) {
		loadThemes();
		allThemes.remove(newTheme);
		allThemes.add(newTheme);
	}

	@Override
	public void deleteTheme(GTheme theme) {
		File file = theme.getFile();
		if (file != null) {
			file.delete();
		}
		if (allThemes != null) {
			allThemes.remove(theme);
		}
	}

	@Override
	public Set<GTheme> getAllThemes() {
		loadThemes();
		return new HashSet<>(allThemes);
	}

	@Override
	public Set<GTheme> getSupportedThemes() {
		loadThemes();
		Set<GTheme> supported = new HashSet<>();
		for (GTheme theme : allThemes) {
			if (theme.hasSupportedLookAndFeel()) {
				supported.add(theme);
			}
		}
		return supported;
	}

	@Override
	public GTheme getActiveTheme() {
		return activeTheme;
	}

	@Override
	public LafType getLookAndFeelType() {
		return activeTheme.getLookAndFeelType();
	}

	@Override
	public GTheme getTheme(String themeName) {
		Optional<GTheme> first =
			getAllThemes().stream().filter(t -> t.getName().equals(themeName)).findFirst();
		return first.orElse(null);
	}

	@Override
	public GThemeValueMap getThemeValues() {
		GThemeValueMap map = new GThemeValueMap();
		map.load(javaDefaults);
		map.load(systemValues);
		map.load(applicationDefaults);
		if (activeTheme.useDarkDefaults()) {
			map.load(applicationDarkDefaults);
		}
		map.load(activeTheme);
		return map;
	}

	@Override
	public void setFont(FontValue newValue) {
		FontValue currentValue = currentValues.getFont(newValue.getId());
		if (newValue.equals(currentValue)) {
			return;
		}
		updateChangedValuesMap(currentValue, newValue);

		currentValues.addFont(newValue);
		notifyThemeChanged(new FontChangedThemeEvent(currentValues, newValue));

		// update all java LookAndFeel fonts affected by this changed
		String id = newValue.getId();
		Set<String> changedFontIds = findChangedJavaFontIds(id);
		lookAndFeelManager.fontsChanged(changedFontIds);
	}

	@Override
	public void setColor(ColorValue newValue) {
		ColorValue currentValue = currentValues.getColor(newValue.getId());
		if (newValue.equals(currentValue)) {
			return;
		}
		updateChangedValuesMap(currentValue, newValue);
		currentValues.addColor(newValue);
		notifyThemeChanged(new ColorChangedThemeEvent(currentValues, newValue));

		// now update the ui
		if (lookAndFeelManager != null) {
			lookAndFeelManager.colorsChanged();
		}
	}

	@Override
	public void setIcon(IconValue newValue) {
		IconValue currentValue = currentValues.getIcon(newValue.getId());
		if (newValue.equals(currentValue)) {
			return;
		}
		updateChangedValuesMap(currentValue, newValue);

		currentValues.addIcon(newValue);
		notifyThemeChanged(new IconChangedThemeEvent(currentValues, newValue));

		// now update the ui
		// update all java LookAndFeel icons affected by this changed
		String id = newValue.getId();
		Set<String> changedIconIds = findChangedJavaIconIds(id);
		Icon newIcon = newValue.get(currentValues);
		lookAndFeelManager.iconsChanged(changedIconIds, newIcon);
	}

	@Override
	public GColorUIResource getGColorUiResource(String id) {
		GColorUIResource gColor = gColorMap.get(id);
		if (gColor == null) {
			gColor = new GColorUIResource(id);
			gColorMap.put(id, gColor);
		}
		return gColor;
	}

	@Override
	public GIconUIResource getGIconUiResource(String id) {

		GIconUIResource gIcon = gIconMap.get(id);
		if (gIcon == null) {
			gIcon = new GIconUIResource(id);
			gIconMap.put(id, gIcon);
		}
		return gIcon;
	}

	@Override
	public GThemeValueMap getJavaDefaults() {
		GThemeValueMap map = new GThemeValueMap();
		map.load(javaDefaults);
		return map;
	}

	@Override
	public GThemeValueMap getApplicationDarkDefaults() {
		GThemeValueMap map = new GThemeValueMap(applicationDefaults);
		map.load(applicationDarkDefaults);
		return map;
	}

	@Override
	public GThemeValueMap getApplicationLightDefaults() {
		GThemeValueMap map = new GThemeValueMap(applicationDefaults);
		return map;
	}

	/**
	 * Returns a {@link GThemeValueMap} containing all default values for the current theme. It
	 * is a combination of application defined defaults and java {@link LookAndFeel} defaults.
	 * @return the current set of defaults.
	 */
	public GThemeValueMap getDefaults() {
		GThemeValueMap currentDefaults = new GThemeValueMap(javaDefaults);
		currentDefaults.load(systemValues);
		currentDefaults.load(applicationDefaults);
		if (activeTheme.useDarkDefaults()) {
			currentDefaults.load(applicationDarkDefaults);
		}
		return currentDefaults;
	}

	/**
	 * Sets specially defined system UI values.  These values are created by the application as a
	 * convenience for mapping generic concepts to values that differ by Look and Feel.  This allows
	 * clients to use 'system' properties without knowing the actual Look and Feel terms.
	 * 
	 * <p>For example, 'system.color.border' defaults to 'controlShadow', but maps to 'nimbusBorder'
	 * in the Nimbus Look and Feel.
	 * 
	 * @param map the map
	 */
	public void setSystemDefaults(GThemeValueMap map) {
		systemValues = map;
	}

	/**
	 * Sets the map of Java default UI values. These are the UI values defined by the current Java 
	 * Look and Feel.
	 * @param map the default theme values defined by the {@link LookAndFeel}
	 */
	public void setJavaDefaults(GThemeValueMap map) {
		javaDefaults = map;
		buildCurrentValues();
		GColor.refreshAll(currentValues);
		GIcon.refreshAll(currentValues);
	}

	@Override
	public boolean isUsingAquaUI(ComponentUI UI) {
		return activeTheme.getLookAndFeelType() == LafType.MAC;
	}

	@Override
	public boolean isUsingNimbusUI() {
		return activeTheme.getLookAndFeelType() == LafType.NIMBUS;
	}

	@Override
	public boolean hasThemeChanges() {
		return !changedValuesMap.isEmpty();
	}

	@Override
	public void registerFont(Component component, String fontId) {
		lookAndFeelManager.registerFont(component, fontId);
	}

	public boolean isDarkTheme() {
		return activeTheme.useDarkDefaults();
	}

	private void installFlatLookAndFeels() {
		UIManager.installLookAndFeel(LafType.FLAT_LIGHT.getName(), FlatLightLaf.class.getName());
		UIManager.installLookAndFeel(LafType.FLAT_DARK.getName(), FlatDarkLaf.class.getName());
	}

	private void loadThemeDefaults() {
		themeFileLoader.loadThemeDefaultFiles();
		applicationDefaults = themeFileLoader.getDefaults();
		applicationDarkDefaults = themeFileLoader.getDarkDefaults();
	}

	private void buildCurrentValues() {
		GThemeValueMap map = new GThemeValueMap();

		map.load(javaDefaults);
		map.load(systemValues);
		map.load(applicationDefaults);
		if (activeTheme.useDarkDefaults()) {
			map.load(applicationDarkDefaults);
		}
		map.load(activeTheme);
		currentValues = map;
		changedValuesMap.clear();
	}

	private void loadThemes() {
		if (allThemes == null) {
			Set<GTheme> set = new HashSet<>();
			set.addAll(findDiscoverableThemes());
			set.addAll(themeFileLoader.loadThemeFiles());
			allThemes = set;
		}
	}

	private Collection<DiscoverableGTheme> findDiscoverableThemes() {
		return ClassSearcher.getInstances(DiscoverableGTheme.class);
	}

	private void updateChangedValuesMap(ColorValue currentValue, ColorValue newValue) {
		String id = newValue.getId();
		ColorValue originalValue = changedValuesMap.getColor(id);

		// if new value is original value, it is no longer changed, remove it from changed map
		if (newValue.equals(originalValue)) {
			changedValuesMap.removeColor(id);
		}
		else if (originalValue == null) {
			// first time changed, so current value is original value
			changedValuesMap.addColor(currentValue);
		}
	}

	private void updateChangedValuesMap(FontValue currentValue, FontValue newValue) {
		String id = newValue.getId();
		FontValue originalValue = changedValuesMap.getFont(id);

		// if new value is original value, it is no longer changed, remove it from changed map
		if (newValue.equals(originalValue)) {
			changedValuesMap.removeFont(id);
		}
		else if (originalValue == null) {
			// first time changed, so current value is original value
			changedValuesMap.addFont(currentValue);
		}
	}

	private void updateChangedValuesMap(IconValue currentValue, IconValue newValue) {
		String id = newValue.getId();
		IconValue originalValue = changedValuesMap.getIcon(id);

		// if new value is original value, it is no longer changed, remove it from changed map
		if (newValue.equals(originalValue)) {
			changedValuesMap.removeIcon(id);
		}
		else if (originalValue == null) {
			// first time changed, so current value is original value
			changedValuesMap.addIcon(currentValue);
		}
	}

	private Set<String> findChangedJavaFontIds(String id) {
		Set<String> affectedIds = new HashSet<>();
		List<FontValue> fonts = javaDefaults.getFonts();
		for (FontValue fontValue : fonts) {
			String fontId = fontValue.getId();
			FontValue currentFontValue = currentValues.getFont(fontId);
			if (fontId.equals(id) || currentFontValue.inheritsFrom(id, currentValues)) {
				affectedIds.add(fontId);
			}
		}
		return affectedIds;
	}

	private Set<String> findChangedJavaIconIds(String id) {
		Set<String> affectedIds = new HashSet<>();
		List<IconValue> icons = javaDefaults.getIcons();
		for (IconValue iconValue : icons) {
			String iconId = iconValue.getId();
			if (iconId.equals(id) || iconValue.inheritsFrom(id, currentValues)) {
				affectedIds.add(iconId);
			}
		}
		return affectedIds;
	}

	public void refreshGThemeValues() {
		GColor.refreshAll(currentValues);
		GIcon.refreshAll(currentValues);
	}

}
