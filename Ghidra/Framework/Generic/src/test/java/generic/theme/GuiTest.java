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

import static ghidra.util.WebColors.*;
import static org.junit.Assert.*;

import java.awt.Color;
import java.awt.Font;
import java.net.URL;
import java.util.*;

import javax.swing.Icon;
import javax.swing.JLabel;
import javax.swing.plaf.UIResource;

import org.junit.Before;
import org.junit.Test;

import generic.theme.builtin.*;
import resources.ResourceManager;
import resources.icons.UrlImageIcon;

public class GuiTest {

	private Font FONT = new Font("Dialog", Font.PLAIN, 13);
	private Font SMALL_FONT = new Font("Dialog", Font.PLAIN, 4);

	private Icon ICON1 = ResourceManager.loadImage("images/exec.png");
	private Icon ICON2 = ResourceManager.loadImage("images/flag.png");

	private GThemeValueMap defaultValues = new GThemeValueMap();
	private GThemeValueMap darkDefaultValues = new GThemeValueMap();
	private Set<GTheme> themes;
	private GTheme METAL_THEME = new MetalTheme();
	private GTheme NIMBUS_THEME = new NimbusTheme();
	private GTheme WINDOWS_THEME = new WindowsTheme();
	private GTheme MAC_THEME = new MacTheme();

	@Before
	public void setUp() {
		themes = new HashSet<>();
		themes.add(METAL_THEME);
		themes.add(NIMBUS_THEME);
		themes.add(WINDOWS_THEME);
		themes.add(MAC_THEME);

		defaultValues.addColor(new ColorValue("color.test.bg", WHITE));
		defaultValues.addColor(new ColorValue("color.test.fg", RED));

		defaultValues.addFont(new FontValue("font.test.foo", FONT));
		defaultValues.addIcon(new IconValue("icon.test.foo", ICON1));

		darkDefaultValues.addColor(new ColorValue("color.test.bg", BLACK));
		darkDefaultValues.addColor(new ColorValue("color.test.fg", BLUE));

		Gui.setThemePreferenceManager(new ThemePreferenceManager() {

			public GTheme getTheme() {
				return new MetalTheme();
			}

			@Override
			public void saveThemeToPreferences(GTheme theme) {
				// do nothing
			}
		});

		Gui.setPropertiesLoader(new ThemeFileLoader() {

			@Override
			public void loadThemeDefaultFiles() {
				// do nothing
			}

			@Override
			public Collection<GTheme> loadThemeFiles() {
				return new HashSet<>(themes);
			}

			@Override
			public GThemeValueMap getDefaults() {
				return defaultValues;
			}

			@Override
			public GThemeValueMap getDarkDefaults() {
				return darkDefaultValues;
			}
		});
		Gui.initialize();
	}

	@Test
	public void testDarkThemeColorOverride() {
		GColor gColor = new GColor("color.test.bg");

		assertColor(WHITE, gColor);
		Gui.setTheme(new GTheme("Test", LafType.FLAT_DARK, true));
		assertEquals(BLACK, gColor);

		Gui.setTheme(new GTheme("Test2"));
		assertEquals(WHITE, gColor);

	}

	@Test
	public void testThemeColorOverride() {
		GColor gColor = new GColor("color.test.bg");

		GTheme theme = new GTheme("Test");
		theme.setColor("color.test.bg", GREEN);

		assertColor(WHITE, gColor);
		Gui.setTheme(theme);
		assertEquals(GREEN, gColor);

		Gui.setTheme(new GTheme("Test2"));
		assertEquals(WHITE, gColor);
	}

	@Test
	public void testThemeFontOverride() {
		assertEquals(FONT, Gui.getFont("font.test.foo"));

		GTheme theme = new GTheme("Test");
		theme.setFont("font.test.foo", SMALL_FONT);
		Gui.setTheme(theme);

		assertEquals(SMALL_FONT, Gui.getFont("font.test.foo"));

		Gui.setTheme(new GTheme("Test2"));
		assertEquals(FONT, Gui.getFont("font.test.foo"));
	}

	@Test
	public void testThemeIconOverride() {
		GIcon gIcon = new GIcon("icon.test.foo");

		GTheme theme = new GTheme("Test");
		theme.setIcon("icon.test.foo", ICON2);

		assertIcon(ICON1, gIcon);
		Gui.setTheme(theme);
		assertIcon(ICON2, gIcon);

		Gui.setTheme(new GTheme("Test2"));
		assertIcon(ICON1, gIcon);
	}

	@Test
	public void testReloadGhidraDefaults() {
		GColor gColor = new GColor("color.test.bg");
		assertColor(WHITE, gColor);

		defaultValues.addColor(new ColorValue("color.test.bg", YELLOW));
		Gui.reloadApplicationDefaults();
		assertEquals(YELLOW, gColor);
	}

	@Test
	public void testRestoreThemeValues() {
		GColor gColor = new GColor("color.test.bg");
		assertColor(WHITE, gColor);

		Gui.setColor("color.test.bg", PURPLE);
		assertColor(PURPLE, gColor);

		Gui.restoreThemeValues();
		assertEquals(WHITE, gColor);

	}

	@Test
	public void testGetAllThemes() {
		assertEquals(themes, Gui.getAllThemes());
	}

	@Test
	public void testAddTheme() {
		GTheme newTheme = new GTheme("Test");

		Set<GTheme> allThemes = Gui.getAllThemes();
		assertEquals(themes.size(), allThemes.size());
		assertFalse(allThemes.contains(newTheme));

		Gui.addTheme(newTheme);
		allThemes = Gui.getAllThemes();
		assertTrue(allThemes.contains(newTheme));
	}

	@Test
	public void testDeleteTheme() {
		GTheme newTheme = new GTheme("Test");
		Set<GTheme> allThemes = Gui.getAllThemes();
		assertFalse(allThemes.contains(newTheme));

		Gui.addTheme(newTheme);
		allThemes = Gui.getAllThemes();
		assertTrue(allThemes.contains(newTheme));

		Gui.deleteTheme(newTheme);
		allThemes = Gui.getAllThemes();
		assertFalse(allThemes.contains(newTheme));
	}

	@Test
	public void testGetSupportedThemes() {
		Set<GTheme> supportedThemes = Gui.getSupportedThemes();
		// since we put mac specific and windows specific themes, they can't all be here
		// regardless of the current platform
		assertTrue(supportedThemes.size() < themes.size());
		for (GTheme gTheme : supportedThemes) {
			assertTrue(gTheme.hasSupportedLookAndFeel());
		}
	}

	@Test
	public void testGetLookAndFeelType() {
		LafType lookAndFeelType = Gui.getLookAndFeelType();
		// in the test setup, we defaulted to the MetalLookAndFeel
		assertEquals(LafType.METAL, lookAndFeelType);
	}

	@Test
	public void testGetActiveTheme() {
		GTheme activeTheme = Gui.getActiveTheme();
		assertEquals(METAL_THEME, activeTheme);
	}

	@Test
	public void testGetThemeByName() {
		GTheme theme = Gui.getTheme("Nimbus Theme");
		assertEquals(NIMBUS_THEME, theme);
	}

	@Test
	public void testGetAllValues() {
		GThemeValueMap allValues = Gui.getAllValues();
		assertEquals(WHITE, allValues.getColor("color.test.bg").getRawValue());

		Gui.setColor("color.test.bg", PURPLE);

		allValues = Gui.getAllValues();
		assertEquals(PURPLE, allValues.getColor("color.test.bg").getRawValue());

	}

	@Test
	public void testGetNonDefaultValues() {
		// should be empty if we haven't changed any themeValues
		GThemeValueMap nonDefaultValues = Gui.getNonDefaultValues();
		assertTrue(nonDefaultValues.isEmpty());

		// change some values and see that they show up in the nonDefaultValues
		Gui.setColor("color.test.bg", RED);
		Gui.setFont("font.test.foo", SMALL_FONT);
		Gui.setIcon("icon.test.foo", ICON2);
		// also add in a totally new value
		Gui.setColor("color.test.xxx", GREEN);

		nonDefaultValues = Gui.getNonDefaultValues();
		assertEquals(4, nonDefaultValues.size());
		assertEquals(RED, nonDefaultValues.getColor("color.test.bg").getRawValue());
		assertEquals(GREEN, nonDefaultValues.getColor("color.test.xxx").getRawValue());
		assertEquals(SMALL_FONT, nonDefaultValues.getFont("font.test.foo").getRawValue());
		assertEquals(ICON2, nonDefaultValues.getIcon("icon.test.foo").getRawValue());
	}

	@Test
	public void testGetColor() {
		assertEquals(WHITE, Gui.getColor("color.test.bg"));
	}

	@Test
	public void testGetFont() {
		assertEquals(FONT, Gui.getFont("font.test.foo"));
	}

	@Test
	public void testGetIcon() {
		assertEquals(ICON1, Gui.getIcon("icon.test.foo"));
	}

	@Test
	public void testGetColorWithUnresolvedId() {
		assertEquals(CYAN, Gui.getColor("color.badid", false));
	}

	@Test
	public void testGetIconWithUnresolvedId() {
		assertEquals(ResourceManager.getDefaultIcon(), Gui.getIcon("icon.badid", false));
	}

	@Test
	public void testGetFontWithUnresolvedId() {
		assertEquals(Gui.DEFAULT_FONT, Gui.getFont("font.badid", false));
	}

	@Test
	public void testGetGColorUiResource() {
		Color color = Gui.getGColorUiResource("color.test.bg");
		assertTrue(color instanceof UIResource);

		// make sure there is only one instance for an id;
		Color color2 = Gui.getGColorUiResource("color.test.bg");
		assertTrue(color == color2);
	}

	@Test
	public void testGetGIconUiResource() {
		Icon icon = Gui.getGIconUiResource("icon.test.foo");
		assertTrue(icon instanceof UIResource);

		// make sure there is only one instance for an id;
		Icon gIcon2 = Gui.getGIconUiResource("icon.test.foo");
		assertTrue(icon == gIcon2);
	}

	@Test
	public void testGetApplicationLightDefaults() {
		assertEquals(defaultValues, Gui.getApplicationLightDefaults());
	}

	@Test
	public void testGetApplicationDarkDefaults() {
		// dark defaults are a combination of standard defalts overlayed with dark defaults
		GThemeValueMap expected = new GThemeValueMap();
		expected.load(defaultValues);
		expected.load(darkDefaultValues);
		assertEquals(expected, Gui.getApplicationDarkDefaults());
	}

	@Test
	public void testRegisterFont() {
		Gui.setFont(new FontValue("font.test", SMALL_FONT));
		JLabel label = new JLabel("Test");
		assertNotEquals(SMALL_FONT, label.getFont());
		Gui.registerFont(label, "font.test");
		assertEquals(SMALL_FONT, label.getFont());
		Gui.setFont(new FontValue("font.test", FONT));
		assertEquals(FONT, label.getFont());
	}

	private void assertColor(Color color, GColor gColor) {
		if (color.getRGB() != gColor.getRGB()) {
			fail("RGB values don't match! Expected " + color + " but got " + gColor);
		}
	}

	private void assertIcon(Icon icon, GIcon gIcon) {
		URL url = ((UrlImageIcon) icon).getUrl();
		URL gUrl = gIcon.getUrl();
		if (!url.equals(gUrl)) {
			fail("Icons don't match. Expected " + url + ", but got " + gUrl);
		}
	}
}
