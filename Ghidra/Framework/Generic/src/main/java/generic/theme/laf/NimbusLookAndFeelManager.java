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

import generic.theme.LafType;

public class NimbusLookAndFeelManager extends LookAndFeelManager {
	private UIDefaults overrides = new UIDefaults();

	public NimbusLookAndFeelManager() {
		super(LafType.NIMBUS);
	}

	@Override
	protected LookAndFeelInstaller getLookAndFeelInstaller() {
		return new NimbusLookAndFeelInstaller();
	}

	@Override
	public void updateColor(String id, Color color, boolean isJavaColor) {
		super.updateColor(id, color, isJavaColor);
	}

	@Override
	public void updateFont(String id, Font font, boolean isJavaFont) {
		if (isJavaFont) {
			overrides.put(id, font);
			updateNimbusOverrides();
		}
		repaintAll();
	}

	@Override
	public void updateIcon(String id, Icon icon, boolean isJavaIcon) {
		if (isJavaIcon) {
			overrides.put(id, icon);
			updateNimbusOverrides();
		}
		repaintAll();
	}

	private void updateNimbusOverrides() {
		UIDefaults defaults = getNimbusOverrides();
		for (Window window : Window.getWindows()) {
			updateNimbusUI(window, defaults);
		}
	}

	private void updateNimbusUI(Component c, UIDefaults defaults) {
		updateNimbusUIComp(c, defaults);
		c.invalidate();
		c.validate();
		c.repaint();
	}

	private UIDefaults getNimbusOverrides() {
		UIDefaults defaults = new UIDefaults();
		defaults.putAll(overrides);
		return defaults;
	}

	private void updateNimbusUIComp(Component c, UIDefaults defaults) {
		if (c instanceof JComponent) {
			JComponent jc = (JComponent) c;
			jc.putClientProperty("Nimbus.Overrides", defaults);
			JPopupMenu jpm = jc.getComponentPopupMenu();
			if (jpm != null) {
				updateNimbusUI(jpm, defaults);
			}
		}
		Component[] children = null;
		if (c instanceof JMenu) {
			children = ((JMenu) c).getMenuComponents();
		}
		else if (c instanceof Container) {
			children = ((Container) c).getComponents();
		}
		if (children != null) {
			for (Component child : children) {
				updateNimbusUIComp(child, defaults);
			}
		}
	}

}
