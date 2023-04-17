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
import javax.swing.plaf.ColorChooserUI;

public class GhidraColorChooser extends JColorChooser {

	private static final String DEFAULT_TITLE = "Please Choose a Color";

	private String title = DEFAULT_TITLE;
	private RecentColorCache historyColorCache = new RecentColorCache();
	private List<Color> recentColors = new ArrayList<>();
	private String activeTabName;

	public GhidraColorChooser() {
		super();

		init();
	}

	public GhidraColorChooser(Color initialColor) {
		super(initialColor);

		init();
	}

	@Override
	public void setUI(ColorChooserUI ui) {
		List<Color> history = getColorHistory();
		List<Color> recents = getRecentColors();

		super.setUI(ui);
		SettableColorSwatchChooserPanel swatchPanel = installSettableColorSwatchChooserPanel();

		swatchPanel.setRecentColors(recents);
		swatchPanel.setHistoryColors(history);
	}

	private void init() {
		JTabbedPane tabbedPane = findTabbedPane(this);
		tabbedPane.addChangeListener(e -> {

			if (!tabbedPane.isShowing()) {
				return;
			}

			int n = tabbedPane.getSelectedIndex();
			if (n != -1) {
				activeTabName = tabbedPane.getTitleAt(n);
			}
		});
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public void addColorToHistory(Color c) {
		historyColorCache.addColor(c);
		installHistoryColors();
	}

	public void setColorHistory(List<Color> colors) {
		for (Color color : colors) {
			historyColorCache.addColor(color);
		}

		installHistoryColors();
	}

	public List<Color> getColorHistory() {
		SettableColorSwatchChooserPanel swatchPanel = getCustomSwatchPanel();
		if (swatchPanel != null) {
			return swatchPanel.getHistoryColors();
		}
		if (historyColorCache != null) { // null during init
			return historyColorCache.getMRUColorList();
		}
		return Collections.emptyList();
	}

	public void setRecentColors(List<Color> colors) {
		recentColors.clear();
		if (colors != null) {
			recentColors.addAll(colors);
		}

		installRecentColors();
	}

	private void installHistoryColors() {
		SettableColorSwatchChooserPanel swatchPanel = installSettableColorSwatchChooserPanel();
		swatchPanel.setHistoryColors(historyColorCache.getMRUColorList());
	}

	private void installRecentColors() {
		SettableColorSwatchChooserPanel swatchPanel = installSettableColorSwatchChooserPanel();
		swatchPanel.setRecentColors(recentColors);
	}

	public List<Color> getRecentColors() {

		List<Color> results = new ArrayList<>();
		SettableColorSwatchChooserPanel swatchPanel = getCustomSwatchPanel();
		if (swatchPanel == null) {
			return results;
		}

		results.addAll(swatchPanel.getRecentColors());
		return results;
	}

	/**
	 * Sets the active tab of this chooser to be the given tab name, if it exists (the color chooser
	 * UI may be different, depending upon the current Look and Feel)
	 * 
	 * @param tabName the tab name
	 */
	public void setActiveTab(String tabName) {
		activeTabName = tabName;
		doSetActiveTab();
	}

	public String getActiveTab() {
		return activeTabName;
	}

	@SuppressWarnings("deprecation")
	public Color showDialog(Component centerOverComponent) {
		OKListener okListener = new OKListener();
		JDialog dialog = createDialog(centerOverComponent, title, true, this, okListener, null);
		dialog.show(); // blocks until user brings dialog down...

		Color color = okListener.getColor();
		if (color != null) {
			historyColorCache.addColor(color);
		}
		return color; // null if the user cancels
	}

	private void doSetActiveTab() {
		if (activeTabName == null) {
			return;
		}

		JTabbedPane pane = findTabbedPane(this);
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

	private SettableColorSwatchChooserPanel getCustomSwatchPanel() {

		AbstractColorChooserPanel[] chooserPanels = getChooserPanels();
		if (chooserPanels != null & chooserPanels.length > 1) {
			AbstractColorChooserPanel panel = chooserPanels[0];
			if (panel instanceof SettableColorSwatchChooserPanel) {
				return (SettableColorSwatchChooserPanel) panel;
			}
		}
		return null;
	}

	private SettableColorSwatchChooserPanel installSettableColorSwatchChooserPanel() {

		SettableColorSwatchChooserPanel swatchPanel = getCustomSwatchPanel();
		if (swatchPanel != null) {
			return swatchPanel; // already installed
		}

		AbstractColorChooserPanel[] chooserPanels = getChooserPanels();
		SettableColorSwatchChooserPanel newSwatchPanel =
			new SettableColorSwatchChooserPanel();
		AbstractColorChooserPanel[] newChooserPanels =
			new AbstractColorChooserPanel[chooserPanels.length];
		newChooserPanels[0] = newSwatchPanel;
		for (int i = 1; i < chooserPanels.length; i++) {
			AbstractColorChooserPanel panel = chooserPanels[i];
			newChooserPanels[i] = panel;
		}

		setChooserPanels(newChooserPanels);
		return newSwatchPanel;
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
		private static final int MAX_SIZE = 35; // the number of squares in the UI

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
