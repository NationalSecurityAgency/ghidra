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

import static org.junit.Assert.*;

import java.awt.Color;
import java.awt.Font;
import java.util.Map;

import javax.swing.Icon;
import javax.swing.UIDefaults;

import org.junit.Before;
import org.junit.Test;

import generic.theme.*;
import ghidra.util.Msg;
import ghidra.util.SpyErrorLogger;
import resources.ResourceManager;

public class UIDefaultsMapperTest {

	private Icon ICON = ResourceManager.loadImage("images/exec.png");
	private Font SMALL_FONT = new Font("Dialog", Font.PLAIN, 4);
	private Font FONT = new Font("Dialog", Font.PLAIN, 13);
	private UIDefaults defaults;
	private UiDefaultsMapper mapper;

	@Before
	public void setup() {

		// disable warning messages when some default UI values cannot be found
		Msg.setErrorLogger(new SpyErrorLogger());

		defaults = createDefaults();
		defaults.put("control", Color.RED);
		defaults.put("Button.background", Color.RED);
		defaults.put("Button.font", FONT);
		defaults.put("CheckBox.icon", ICON);

	}

	@Test
	public void testGetJavaDefaults() {
		mapper = new UiDefaultsMapper(defaults);
		GThemeValueMap javaDefaults = mapper.getNormalizedJavaDefaults();

		assertEquals(Color.RED, javaDefaults.getResolvedColor("system.color.bg.control"));
		assertEquals(Color.RED, javaDefaults.getResolvedColor("laf.color.Button.background"));

		assertEquals(FONT, javaDefaults.getResolvedFont("laf.font.Button.font"));
		assertEquals(ICON, javaDefaults.getResolvedIcon("laf.icon.CheckBox.icon"));

		assertIndirectColor(javaDefaults, "laf.color.Button.background", "system.color.bg.control");
		assertIndirectFont(javaDefaults, "laf.font.Button.font", "system.font.control");
		assertDirectIcon(javaDefaults, "laf.icon.CheckBox.icon", ICON);
	}

	@Test
	public void testGetJavaDefaultsNoGroupCreatesPaletteColors() {
		defaults.put("CheckBox.background", Color.GREEN);		// Green not defined in a color group
		defaults.put("ToggleButton.background", Color.GREEN);	// Green not defined in a color group
		defaults.put("RadioButton.background", Color.BLUE);		// Blue not defined in a color group
		mapper = new UiDefaultsMapper(defaults);

		GThemeValueMap javaDefaults = mapper.getNormalizedJavaDefaults();

		// expecting two palette groups to be created
		String greenPalette = findPaletteColor(javaDefaults, Color.GREEN);
		String bluePalette = findPaletteColor(javaDefaults, Color.BLUE);

		assertIndirectColor(javaDefaults, "laf.color.Button.background", "system.color.bg.control");
		assertIndirectColor(javaDefaults, "laf.color.CheckBox.background", greenPalette);
		assertIndirectColor(javaDefaults, "laf.color.ToggleButton.background", greenPalette);
		assertIndirectColor(javaDefaults, "laf.color.RadioButton.background", bluePalette);
		assertDirectColor(javaDefaults, "system.color.bg.control", Color.RED);
	}

	@Test
	public void testGetJavaDefaultsNoGroupCreatesPaletteFonts() {
		defaults.put("CheckBox.font", SMALL_FONT);	// SMALL_FONT not defined in a font group
		defaults.put("ToggleButton.font", SMALL_FONT);	// Green not defined in a color group
		mapper = new UiDefaultsMapper(defaults);

		GThemeValueMap javaDefaults = mapper.getNormalizedJavaDefaults();

		assertDirectFont(javaDefaults, "laf.palette.font.01", SMALL_FONT);
		assertIndirectFont(javaDefaults, "laf.font.ToggleButton.font", "laf.palette.font.01");
		assertIndirectFont(javaDefaults, "laf.font.CheckBox.font", "laf.palette.font.01");
		assertIndirectFont(javaDefaults, "laf.font.Button.font", "system.font.control");

	}

	@Test
	public void testInstallValuesIntoUiDefaults() {
		mapper = new UiDefaultsMapper(defaults);
		mapper.installValuesIntoUIDefaults(new GThemeValueMap());

		assertEquals(new GColorUIResource("laf.color.Button.background"),
			defaults.getColor("Button.background"));
		assertEquals(FONT, defaults.getFont("Button.font"));
		assertEquals(ICON, defaults.getIcon("CheckBox.icon"));
	}

	@Test
	public void testGetNormalizedIdToLafidMap() {
		mapper = new UiDefaultsMapper(defaults);
		Map<String, String> map = mapper.getNormalizedIdToLafIdMap();
		assertEquals("Button.background", map.get("laf.color.Button.background"));
		assertEquals("Button.font", map.get("laf.font.Button.font"));
		assertEquals("CheckBox.icon", map.get("laf.icon.CheckBox.icon"));
	}

	private void assertDirectColor(GThemeValueMap javaDefaults, String id, Color color) {
		ColorValue colorValue = javaDefaults.getColor(id);
		assertEquals(color, colorValue.getRawValue());
	}

	private void assertDirectFont(GThemeValueMap javaDefaults, String id, Font font) {
		FontValue fontValue = javaDefaults.getFont(id);
		assertEquals(font, fontValue.getRawValue());
	}

	private void assertIndirectColor(GThemeValueMap javaDefaults, String id, String indirectId) {
		ColorValue colorValue = javaDefaults.getColor(id);
		assertEquals(indirectId, colorValue.getReferenceId());
	}

	private void assertIndirectFont(GThemeValueMap javaDefaults, String id, String indirectId) {
		FontValue fontValue = javaDefaults.getFont(id);
		assertEquals(indirectId, fontValue.getReferenceId());
	}

	private void assertDirectIcon(GThemeValueMap javaDefaults, String id, Icon icon) {
		IconValue iconValue = javaDefaults.getIcon(id);
		assertEquals(icon, iconValue.getRawValue());
	}

	private String findPaletteColor(GThemeValueMap javaDefaults, Color color) {
		for (ColorValue colorValue : javaDefaults.getColors()) {
			if (colorValue.getId().contains("palette.color") &&
				colorValue.getRawValue().equals(color)) {
				return colorValue.getId();
			}
		}
		fail("Could not find pallete color for " + color);
		return null;
	}

	private UIDefaults createDefaults() {
		// populate defaults with standard laf group values, to avoid warning messages complaining
		// about them being undefined
		UIDefaults uiDefaults = new UIDefaults();
		uiDefaults.put("control", Color.BLACK);				// for laf.group.control.color.bg
		uiDefaults.put("controlText", Color.BLACK);			// for laf.group.control.color.fg
		uiDefaults.put("controlShadow", Color.BLACK);		// for laf.group.control.color.border
		uiDefaults.put("window", Color.BLACK);				// for laf.group.view.color.bg
		uiDefaults.put("windowText", Color.BLACK);			// for laf.group.view.color.fg
		uiDefaults.put("textHighlight", Color.BLACK);		// for laf.group.view.color.bg.selected and laf.group.text.color.bg.selected
		uiDefaults.put("textHighlightText", Color.BLACK);   // for laf.group.view.color.fg.selected and laf.group.text.color.fg.selected

		uiDefaults.put("textText", Color.BLACK);			// for laf.group.text.color.fg	
		uiDefaults.put("text", Color.BLACK);				// for laf.group.text.color.bg
		uiDefaults.put("textInactiveText", Color.BLACK);	// for laf.group.text.color.fg.disabled
		uiDefaults.put("info", Color.BLACK);				// for laf.group.tooltip.color.bg
		uiDefaults.put("infoText", Color.BLACK);			// for laf.group.tooltip.color.fg

		uiDefaults.put("Panel.font", FONT);		// for laf.group.control.font
		uiDefaults.put("TextField.font", FONT);	// for laf.group.text.font
		uiDefaults.put("Table.font", FONT);		// for laf.group.view.font
		uiDefaults.put("Menu.font", FONT);		// for laf.group.menu.font

		return uiDefaults;
	}
}
