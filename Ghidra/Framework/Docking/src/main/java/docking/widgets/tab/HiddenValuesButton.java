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

import java.awt.Color;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.Border;

import docking.widgets.label.GDLabel;
import generic.theme.*;

/**
 * Component displayed when not all tabs fit on the tab panel and is used to display a popup
 * list of all tabs.
 */
public class HiddenValuesButton extends GDLabel {
	//@formatter:off
	private static final String FONT_TABS_LIST_ID = "font.widget.tabs.list";
	private static final Icon LIST_ICON = new GIcon("icon.widget.tabs.list");
	private static final Color BG_COLOR_MORE_TABS_HOVER = new GColor("color.bg.widget.tabs.more.tabs.hover");
	private static final String DEFAULT_HIDDEN_COUNT_STR = "99";
	//@formatter:on

	private Border defaultListLabelBorder;

	HiddenValuesButton(GTabPanel<?> tabPanel) {
		super(DEFAULT_HIDDEN_COUNT_STR, LIST_ICON, SwingConstants.LEFT);
		setName("Hidden Values Control");
		setIconTextGap(2);
		Gui.registerFont(this, FONT_TABS_LIST_ID);
		setBorder(BorderFactory.createEmptyBorder(4, 4, 0, 4));
		setToolTipText("Show Tab List");
		getAccessibleContext().setAccessibleName("Show Hidden Values List");
		setBackground(BG_COLOR_MORE_TABS_HOVER);

		defaultListLabelBorder = getBorder();
		Border hoverBorder = BorderFactory.createBevelBorder(BevelBorder.RAISED);
		addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if (tabPanel.isListWindowShowing()) {
					tabPanel.closeTabList();
					return;
				}
				tabPanel.showTabList(true);
			}

			@Override
			public void mouseEntered(MouseEvent e) {
				// show a raised border, like a button (if the window is not already visible)
				if (tabPanel.isListWindowShowing()) {
					return;
				}

				setBorder(hoverBorder);
				setOpaque(true);
			}

			@Override
			public void mouseExited(MouseEvent e) {
				setBorder(defaultListLabelBorder);
				setOpaque(false);
			}
		});

		setPreferredSize(getPreferredSize());
	}

	void setHiddenCount(int count) {
		setText(Integer.toString(count));
	}

	int getPreferredWidth() {
		return getPreferredSize().width;
	}
}
