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
package docking.help;

import java.awt.Component;
import java.awt.Graphics;
import java.awt.event.ActionEvent;

import javax.swing.*;

import ghidra.framework.preferences.Preferences;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.CenterTranslateIcon;
import resources.icons.TranslateIcon;

public class ToggleNavigationAid extends AbstractAction {

	private static final Icon ENABLED_ICON =
		ResourceManager.loadImage("images/software-update-available.png");
	private static final Icon CANCEL_ICON = ResourceManager.loadImage("images/dialog-cancel.png");
	private static Icon DISABLED_ICON;

	private boolean showingNavigationAid = true;

	public ToggleNavigationAid() {

		putValue(Action.SMALL_ICON, new SelfPaintingIcon());
		putValue(Action.SHORT_DESCRIPTION,
			"Paints an on-screen marker to show the current location " +
				"when navigating within the help system");

		TranslateIcon translatedIcon =
			new CenterTranslateIcon(CANCEL_ICON, ENABLED_ICON.getIconWidth());
		ImageIcon disabledBaseIcon = ResourceManager.getDisabledIcon(ENABLED_ICON, 50);
		DISABLED_ICON = new MultiIcon(disabledBaseIcon, translatedIcon);

		// initialize
		String value = Preferences.getProperty(HelpManager.SHOW_AID_KEY);
		if (value != null) {
			showingNavigationAid = Boolean.parseBoolean(value);
		}
		else {
			// not yet in the preferences; save the default 
			savePreference();
		}
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		showingNavigationAid = !showingNavigationAid;
		savePreference();
	}

	private void savePreference() {
		Preferences.setProperty(HelpManager.SHOW_AID_KEY, Boolean.toString(showingNavigationAid));
		Preferences.store();
	}

	private class SelfPaintingIcon implements Icon {

		@Override
		public void paintIcon(Component c, Graphics g, int x, int y) {
			Icon icon = getIcon();
			icon.paintIcon(c, g, x, y);
		}

		private Icon getIcon() {
			return showingNavigationAid ? ENABLED_ICON : DISABLED_ICON;
		}

		@Override
		public int getIconWidth() {
			return getIcon().getIconWidth();
		}

		@Override
		public int getIconHeight() {
			return getIcon().getIconHeight();
		}
	}

}
