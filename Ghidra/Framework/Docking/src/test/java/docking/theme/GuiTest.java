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

import java.util.List;
import java.util.Map;

import org.apache.commons.collections4.map.HashedMap;
import org.junit.Before;

import docking.test.AbstractDockingTest;

public class GuiTest extends AbstractDockingTest {

	private Map<String, List<String>> aliasMap = new HashedMap<>();
	private GThemeValueMap darkValues = new GThemeValueMap();

	@Before
	public void setUp() {
		Gui.setPropertiesLoader(new ThemePropertiesLoader() {
			@Override
			public void initialize() {
				// do nothing
			}

			@Override
			public GThemeValueMap getDarkDefaults() {
				return darkValues;
			}
		});
	}

//	@Test
//	public void testRegisteredColorBeforeAndAfterGuiInit() {
//		Gui.registerColor("test.before", Color.RED);
//		Gui.initialize();
//		Gui.registerColor("test.after", Color.BLUE);
//
//		assertEquals(Color.RED, Gui.getColor("test.before"));
//		assertEquals(Color.BLUE, Gui.getColor("test.after"));
//	}

//	@Test
//	public void testThemeColorOverride() {
//		Gui.initialize();
//		String id = "color.test.bg";
//		Gui.registerColor(id, Color.RED);
//		assertEquals(Color.RED, Gui.getColor(id));
//
//		GTheme theme = new GTheme("Test");
//		theme.setColor(id, Color.BLUE);
//		Gui.setTheme(theme);
//
//		assertEquals(Color.BLUE, Gui.getColor(id));
//
//		Gui.setTheme(new GTheme("Test2"));
//		assertEquals(Color.RED, Gui.getColor(id));
//
//	}

//	@Test
//	public void testDarkOverride() {
//		String id = "color.test.bg";
//		// simulate registered dark color from theme property file
//		darkValues.addColor(new ColorValue(id, Color.BLACK));
//
//		Gui.registerColor(id, Color.RED);
//		Gui.initialize();
//
//		assertEquals(Color.RED, Gui.getColor(id));
//
//		GTheme theme = new GTheme("Dark Test", "System", true);
//		Gui.setTheme(theme);
//
//		assertEquals(Color.BLACK, Gui.getColor(id));
//	}

//	@Test
//	public void testAliasOverride() {
//		String id = "color.test.bg";
//		//simulate alias defined
//		List<String> aliases = Arrays.asList("Menu.background");
//		aliasMap.put(id, aliases);
//
//		Gui.registerColor(id, Color.RED);
//		Gui.initialize();
//		Color menuColor = UIManager.getColor("Menu.background");
//		assertNotEquals(menuColor, Color.RED);
//		assertEquals(menuColor, Gui.getColor(id));
//	}

//	private void assertEqual(Color a, GColor b) {
//		if (a.getRGB() != b.getRGB()) {
//			fail("Expected: " + a.toString() + " but was: " + b.toString());
//		}
//	}

}
