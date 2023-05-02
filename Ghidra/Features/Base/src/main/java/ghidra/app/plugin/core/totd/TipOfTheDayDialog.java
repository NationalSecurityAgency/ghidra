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
package ghidra.app.plugin.core.totd;

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;

import docking.DockingWindowManager;
import docking.ReusableDialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import generic.theme.GIcon;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.Gui;

class TipOfTheDayDialog extends ReusableDialogComponentProvider {
	private static final String FONT_ID = "font.plugin.tips";
	private static final String FONT_LABEL_ID = "font.plugin.tips.label";
	private static final int _24_HOURS = 86400000;

	private TipOfTheDayPlugin plugin;
	private JCheckBox showTipsCheckbox;
	private JButton nextTipButton;
	private JButton closeButton;
	private JTextArea tipArea;
	private int tipIndex = 0;
	private List<String> tips;

	TipOfTheDayDialog(TipOfTheDayPlugin plugin, List<String> tips) {
		super("Tip of the Day", false, false, true, false);

		this.plugin = plugin;
		this.tips = tips;

		if (tips.isEmpty()) {
			tips.add("Could not find any tips!");
		}

		Icon tipIcon = new GIcon("icon.plugin.totd.provider");

		tipArea = new JTextArea(4, 30);
		tipArea.setEditable(false);
		tipArea.setFont(Gui.getFont(FONT_ID));
		tipArea.setWrapStyleWord(true);
		tipArea.setLineWrap(true);
		tipArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		tipArea.setBackground(Colors.BACKGROUND);

		JScrollPane tipScroll = new JScrollPane(tipArea);
		tipScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		tipScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
		tipScroll.setBorder(BorderFactory.createEmptyBorder());
		tipScroll.setPreferredSize(tipArea.getPreferredSize());

		showTipsCheckbox = new GCheckBox("Show Tips on Startup?");
		showTipsCheckbox.setSelected(true); // before adding the listener to prevent project save
		showTipsCheckbox.addItemListener(e -> showTipsChanged());

		nextTipButton = new JButton("Next Tip");
		nextTipButton.addActionListener(e -> {
			incrementTipIndex();
			loadNextTip();
		});
		addButton(nextTipButton);

		closeButton = new JButton("Close");
		closeButton.addActionListener(e -> close());
		addButton(closeButton);

		JPanel panel = new JPanel(new BorderLayout());
		Border panelBorder =
			BorderFactory.createCompoundBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10),
				BorderFactory.createLineBorder(Colors.BORDER));
		panel.setBorder(panelBorder);

		JLabel label = new GLabel("Did you know...", tipIcon, SwingConstants.LEFT);
		label.setBackground(Colors.BACKGROUND);
		label.setOpaque(true);
		Gui.registerFont(label, FONT_LABEL_ID);
		panel.add(label, BorderLayout.NORTH);

		panel.add(tipScroll, BorderLayout.CENTER);

		JPanel panel2 = new JPanel(new BorderLayout(5, 5));
		panel2.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel2.add(panel, BorderLayout.CENTER);
		panel2.add(showTipsCheckbox, BorderLayout.SOUTH);

		addWorkPanel(panel2);
	}

	private void showTipsChanged() {
		plugin.writePreferences();
	}

	private static long lastTipTime = 0;

	void show(Component parent) {
		long now = System.currentTimeMillis();
		if (now - lastTipTime > _24_HOURS) {
			doShow(parent);
		}
		lastTipTime = now;
	}

	void doShow(Component parent) {
		loadNextTip();
		DockingWindowManager.showDialog(parent, this);
	}

	private void incrementTipIndex() {
		tipIndex = (++tipIndex) % tips.size();
		plugin.writePreferences();
	}

	private void loadNextTip() {
		if (tips.isEmpty()) {
			return;
		}
		if (tipIndex < 0 || tipIndex > tips.size() - 1) {
			return;
		}
		String tip = tips.get(tipIndex);
		tipArea.setText(tip);
	}

	int getTipIndex() {
		return tipIndex;
	}

	int getNumberOfTips() {
		return tips.size();
	}

	boolean showTips() {
		return showTipsCheckbox.isSelected();
	}

	void setTipIndex(int tipIndex) {
		this.tipIndex = tipIndex;
		loadNextTip();
	}

	void setShowTips(boolean showTips) {
		showTipsCheckbox.setSelected(showTips);
	}
}
