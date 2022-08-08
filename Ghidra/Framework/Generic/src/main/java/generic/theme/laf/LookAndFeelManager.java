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

import java.awt.*;

import javax.swing.*;

import generic.theme.*;

/**
 * Manages installing and updating a {@link LookAndFeel}
 */
public abstract class LookAndFeelManager {

	private LafType laf;

	protected LookAndFeelManager(LafType laf) {
		this.laf = laf;
	}

	protected abstract LookAndFeelInstaller getLookAndFeelInstaller();

	public LafType getLookAndFeelType() {
		return laf;
	}

	public void installLookAndFeel() throws ClassNotFoundException, InstantiationException,
			IllegalAccessException, UnsupportedLookAndFeelException {

		LookAndFeelInstaller installer = getLookAndFeelInstaller();
		installer.install();
		updateComponentUis();
	}

	public void update() {
		GColor.refreshAll();
		GIcon.refreshAll();
		updateComponentUis();
//		repaintAll();
	}

	public void updateColor(String id, Color color, boolean isJavaColor) {
		GColor.refreshAll();
		repaintAll();
	}

	public void updateIcon(String id, Icon icon, boolean isJavaIcon) {
		// Icons are a mixed bag. Java Icons are direct and Ghidra Icons are indirect (to support static use)
		// Mainly because Nimbus is buggy and can't handle non-nimbus Icons, so we can't wrap them
		// So need to update UiDefaults for java icons. For Ghidra Icons, it is sufficient to refrech
		// GIcons and repaint
		if (isJavaIcon) {
			UIManager.getDefaults().put(id, icon);
			updateComponentUis();
		}
		GIcon.refreshAll();
		repaintAll();
	}

	public void updateFont(String id, Font font, boolean isJavaFont) {
		if (isJavaFont) {
			UIManager.getDefaults().put(id, font);
			updateComponentUis();
		}
		else {
			repaintAll();
		}

	}

	private void updateComponentUis() {
		for (Window window : Window.getWindows()) {
			SwingUtilities.updateComponentTreeUI(window);
		}
	}

	protected void repaintAll() {
		for (Window window : Window.getWindows()) {
			window.repaint();
		}
	}

}
