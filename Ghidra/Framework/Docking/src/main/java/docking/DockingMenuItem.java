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
package docking;

import java.awt.event.KeyEvent;

import javax.swing.JMenuItem;
import javax.swing.KeyStroke;

import docking.menu.DockingMenuItemUI;
import docking.widgets.GComponent;

public class DockingMenuItem extends JMenuItem implements GComponent {

	public DockingMenuItem() {
		setUI(DockingMenuItemUI.createUI(this));
		setHTMLRenderingEnabled(false);
	}

	@Override
	protected boolean processKeyBinding(KeyStroke ks, KeyEvent e, int condition, boolean pressed) {
		// TODO this note doesn't really make sense.  I think this idea is outdated.  Leaving this
		//      here for a bit, in case there is something we missed.  This code is also in
		//      DockingCheckboxMenuItemUI.
		// return true; // we will take care of the action ourselves

		// Our KeyBindingOverrideKeyEventDispatcher processes actions for us, so there is no
		// need to have the menu item do it
		return false;
	}
}
