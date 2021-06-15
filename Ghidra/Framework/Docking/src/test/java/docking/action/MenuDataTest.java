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
package docking.action;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Tests to protect the MenuData class intended behavior
 */
public class MenuDataTest {

	/**
	 * Mnemonic should be 'T', parsed out of the location of the ampersand in
	 * 3rd argument in the menuPath.
	 * The mnemonic is not explicitly set.
	 */
	@Test
	public void testMenuDataParsesMnemonicFromAmpersand() {
		MenuData menuData = new MenuData(new String[] { "One", "Two", "&Three" });
		assertEquals(menuData.getMnemonic(), 'T');
	}

	/**
	 * Mnemonic should be 'h' based on the value that was explicitly set
	 */
	@Test
	public void testMenuDataPassedMnemonicWins() {
		MenuData menuData = new MenuData(
			new String[] { "One", "Two", "&Three" }, null, null, 'h', null);
		assertEquals(menuData.getMnemonic(), 'h');
	}

	/**
	 * The setMenuPath method should fail to set an invalid (empty) menuPath
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testBreakMenuPath() {
		MenuData menuData = new MenuData(new String[] { "One", "Two", "Three" });
		menuData.setMenuPath(new String[0]);
	}

	/**
	 * The MenuData constructor should fail to accept an invalid (empty) menuPath
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testBreakMenuPath2() {
		new MenuData(new String[] {});
	}

	@Test
	public void testSetMenuItemName() {

		MenuData menuData = new MenuData(new String[] { "One", "Two", "T&hree" });
		assertEquals("Three", menuData.getMenuItemName());
		assertEquals(menuData.getMnemonic(), 'h');

		String newName = "Completely New Name";
		menuData.setMenuItemName(newName);
		assertEquals(menuData.getMnemonic(), MenuData.NO_MNEMONIC);
	}

	@Test
	public void testSetMenuPath() {

		MenuData menuData = new MenuData(new String[] { "One", "Two", "T&hree" });
		assertEquals("Three", menuData.getMenuItemName());
		assertEquals(menuData.getMnemonic(), 'h');

		String newName = "Completely New Name";
		String[] newPath = { "Four", newName };
		menuData.setMenuPath(newPath);
		assertEquals(menuData.getMnemonic(), MenuData.NO_MNEMONIC);
	}
}
