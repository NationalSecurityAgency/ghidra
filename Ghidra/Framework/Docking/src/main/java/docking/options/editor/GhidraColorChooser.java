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
package docking.options.editor;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.colorchooser.AbstractColorChooserPanel;

public class GhidraColorChooser extends JColorChooser {

	private static final String DEFAULT_TITLE = "Please Choose a Color";

	private String title = DEFAULT_TITLE;
	private RecentColorCache recentColorCache = new RecentColorCache();
	private String activeTabName;

	public GhidraColorChooser() {
		super();
	}

	public GhidraColorChooser(Color initialColor) {
		super(initialColor);
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public void setColorHistory(List<Color> colors) {
		for (Color color : colors) {
			recentColorCache.addColor(color);
		}
	}

	public List<Color> getColorHistory() {
		return recentColorCache.getMRUColorList();
	}

	/**
	 * Sets the active tab of this chooser to be the given tab name, if it exists (the color chooser
	 * UI may be different, depending upon the current Look and Feel)
	 * 
	 * @param tabName the tab name
	 */
	public void setActiveTab(String tabName) {
		activeTabName = tabName;
	}

	@SuppressWarnings("deprecation")
	public Color showDialog(Component centerOverComponent) {
		maybeInstallSettableColorSwatchChooserPanel();

		OKListener okListener = new OKListener();
		JDialog dialog = createDialog(centerOverComponent, title, true, this, okListener, null);
		doSetActiveTab(dialog);

		dialog.show(); // blocks until user brings dialog down...
		Color color = okListener.getColor();
		if (color != null) {
			recentColorCache.addColor(color);
		}
		return color; // null if the user cancels
	}

	private void doSetActiveTab(JDialog dialog) {
		if (activeTabName == null) {
			return;
		}

		JTabbedPane pane = findTabbedPane(dialog);
		if (pane == null) {
			return;
		}

		int n = pane.getTabCount();
		for (int i = 0; i < n; i++) {
			String tabTitle = pane.getTitleAt(i);
			if (activeTabName.equals(tabTitle)) {
				pane.setSelectedIndex(i);
				return;
			}
		}
	}

	private JTabbedPane findTabbedPane(Component component) {
		if (!(component instanceof Container)) {
			return null;
		}

		Container parent = (Container) component;
		if (parent instanceof JTabbedPane) {
			return (JTabbedPane) parent;
		}

		int n = parent.getComponentCount();
		for (int i = 0; i < n; i++) {
			Component child = parent.getComponent(i);
			JTabbedPane pane = findTabbedPane(child);
			if (pane != null) {
				return pane;
			}
		}

		return null;
	}

	private void maybeInstallSettableColorSwatchChooserPanel() {
		if (recentColorCache.size() == 0) {
			return;
		}

		List<Color> mruColorList = recentColorCache.getMRUColorList();
		AbstractColorChooserPanel[] chooserPanels = getChooserPanels();
		if (chooserPanels != null & chooserPanels.length > 1) {
			AbstractColorChooserPanel panel = chooserPanels[0];
			if (panel instanceof SettableColorSwatchChooserPanel) {
				// we've already added our panel--reuse
				((SettableColorSwatchChooserPanel) panel).setRecentColors(mruColorList);
				return;
			}
		}

		SettableColorSwatchChooserPanel newSwatchPanel =
			new SettableColorSwatchChooserPanel(mruColorList);
		AbstractColorChooserPanel[] newChooserPanels =
			new AbstractColorChooserPanel[chooserPanels.length];
		newChooserPanels[0] = newSwatchPanel;
		for (int i = 1; i < chooserPanels.length; i++) {
			AbstractColorChooserPanel panel = chooserPanels[i];
			newChooserPanels[i] = panel;
		}

		setChooserPanels(newChooserPanels);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class OKListener implements ActionListener {
		private Color okColor;

		@Override
		public void actionPerformed(ActionEvent e) {
			okColor = GhidraColorChooser.this.getColor();
		}

		Color getColor() {
			return okColor;
		}
	}

	private class RecentColorCache extends LinkedHashMap<Color, Color> implements Iterable<Color> {
		private static final int MAX_SIZE = 15;

		public RecentColorCache() {
			super(16, 0.75f, true);
		}

		@Override
		protected boolean removeEldestEntry(Map.Entry<Color, Color> eldest) {
			return size() > MAX_SIZE;
		}

		@Override
		public Iterator<Color> iterator() {
			return keySet().iterator();
		}

		public void addColor(Color color) {
			put(color, color);
		}

		public List<Color> getMRUColorList() {
			List<Color> list = new ArrayList<>(this.keySet());
			Collections.reverse(list); // we are in LRU order, so reverse it
			return list;
		}
	}
}
