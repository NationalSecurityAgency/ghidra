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
package docking.widgets.tab;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.border.Border;

import docking.widgets.label.GDLabel;
import docking.widgets.label.GIconLabel;
import generic.theme.*;
import ghidra.util.layout.HorizontalLayout;
import resources.Icons;

/**
 * Component for representing individual tabs within a {@link GTabPanel}.
 *
 * @param <T> the type of the tab values
 */
class GTab<T> extends JPanel {
	private final static Border TAB_BORDER = new GTabBorder(false);
	private final static Border SELECTED_TAB_BORDER = new GTabBorder(true);
	private static final String SELECTED_FONT_TABS_ID = "font.widget.tabs.selected";
	private static final String FONT_TABS_ID = "font.widget.tabs";
	private final static Icon EMPTY16_ICON = Icons.EMPTY_ICON;
	private final static Icon CLOSE_ICON = new GIcon("icon.widget.tabs.close");
	private final static Icon HIGHLIGHT_CLOSE_ICON = new GIcon("icon.widget.tabs.close.highlight");
	private final static Color TAB_FG_COLOR = new GColor("color.fg.widget.tabs.unselected");
	private final static Color SELECTED_TAB_FG_COLOR = new GColor("color.fg.widget.tabs.selected");
	private final static Color HIGHLIGHTED_TAB_BG_COLOR =
		new GColor("color.bg.widget.tabs.highlighted");

	final static Color TAB_BG_COLOR = new GColor("color.bg.widget.tabs.unselected");
	final static Color SELECTED_TAB_BG_COLOR = new GColor("color.bg.widget.tabs.selected");

	private GTabPanel<T> tabPanel;
	private T value;
	private boolean selected;
	private JLabel closeLabel;
	private JLabel nameLabel;

	GTab(GTabPanel<T> gTabPanel, T value, boolean selected) {
		super(new HorizontalLayout(10));
		this.tabPanel = gTabPanel;
		this.value = value;
		this.selected = selected;

		setBorder(selected ? SELECTED_TAB_BORDER : TAB_BORDER);

		nameLabel = new GDLabel();
		nameLabel.setName("Tab Label");
		nameLabel.setText(tabPanel.getDisplayName(value));
		nameLabel.setIcon(tabPanel.getValueIcon(value));
		nameLabel.setToolTipText(tabPanel.getValueToolTip(value));
		Gui.registerFont(nameLabel, selected ? SELECTED_FONT_TABS_ID : FONT_TABS_ID);
		add(nameLabel, BorderLayout.WEST);

		closeLabel = new GIconLabel(selected ? CLOSE_ICON : EMPTY16_ICON);
		closeLabel.setToolTipText("Close");
		closeLabel.setName("Close");
		closeLabel.setOpaque(true);
		add(closeLabel, BorderLayout.EAST);

		installMouseListener(this, new GTabMouseListener());

		initializeTabColors(false);
	}

	T getValue() {
		return value;
	}

	void refresh() {
		nameLabel.setText(tabPanel.getDisplayName(value));
		nameLabel.setIcon(tabPanel.getValueIcon(value));
		nameLabel.setToolTipText(tabPanel.getValueToolTip(value));
		repaint();
	}

	void setHighlight(boolean b) {
		initializeTabColors(b);
	}

	private void installMouseListener(Container c, MouseListener listener) {

		c.addMouseListener(listener);
		Component[] children = c.getComponents();
		for (Component element : children) {
			if (element instanceof Container) {
				installMouseListener((Container) element, listener);
			}
			else {
				element.addMouseListener(listener);
			}
		}
	}

	private void initializeTabColors(boolean isHighlighted) {
		Color fg = getForegroundColor(isHighlighted);
		Color bg = getBackgroundColor(isHighlighted);
		setBackground(bg);
		nameLabel.setBackground(bg);
		nameLabel.setForeground(fg);
		closeLabel.setBackground(bg);
	}

	private Color getBackgroundColor(boolean isHighlighted) {
		if (isHighlighted) {
			return HIGHLIGHTED_TAB_BG_COLOR;
		}
		return selected ? SELECTED_TAB_BG_COLOR : TAB_BG_COLOR;
	}

	private Color getForegroundColor(boolean isHighlighted) {
		if (isHighlighted || selected) {
			return SELECTED_TAB_FG_COLOR;
		}
		return TAB_FG_COLOR;
	}

	private class GTabMouseListener extends MouseAdapter {
		@Override
		public void mouseEntered(MouseEvent e) {
			closeLabel.setIcon(e.getSource() == closeLabel ? HIGHLIGHT_CLOSE_ICON : CLOSE_ICON);
		}

		@Override
		public void mouseExited(MouseEvent e) {
			closeLabel.setIcon(selected ? CLOSE_ICON : EMPTY16_ICON);
		}

		@Override
		public void mousePressed(MouseEvent e) {
			// close the list window if the user has clicked outside of the window
			if (!(e.getSource() instanceof JList)) {
				tabPanel.closeTabList();
			}

			if (e.isPopupTrigger()) {
				return; // allow popup triggers to show actions without changing tabs
			}

			if (e.getSource() == closeLabel) {
				tabPanel.closeTab(value);
				return;
			}
			if (!selected) {
				tabPanel.selectTab(value);
			}
		}
	}

}
