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
import java.util.List;

import javax.swing.*;

import docking.widgets.list.GListCellRenderer;
import docking.widgets.searchlist.*;
import generic.util.WindowUtilities;

/**
 * Undecorated dialog for showing a popup window displaying a filterable, scrollable list of tabs
 * in a {@link GTabPanel}.
 *
 * @param <T> the value types
 */
public class TabListPopup<T> extends JDialog {
	private static final String HIDDEN = "Hidden";
	private static final String VISIBLE = "Visible";
	private GTabPanel<T> panel;
	private SearchList<T> searchList;

	TabListPopup(GTabPanel<T> panel, JComponent positioningComponent, String typeName) {
		super(WindowUtilities.windowForComponent(panel));
		setTitle("Popup Window Showing All " + typeName + " Tabs");
		this.panel = panel;
		setUndecorated(true);
		getAccessibleContext().setAccessibleDescription("Use up down arrows to move between " +
			typeName + "tab choices and press enter to select tab. Type text to filter choices. " +
			"Left right arrows to close popup and return focus to visible tabs");

		SearchListModel<T> tabListModel = createTabListModel();
		searchList = new SearchList<T>(tabListModel, (T, C) -> panel.selectTab(T));
		searchList.setItemRenderer(new TabListRenderer());
		searchList.setShowCategories(false);
		searchList.setSingleClickMode(true);
		searchList.setMouseHoverSelection();
		searchList.setDisplayNameFunction((t, c) -> panel.getDisplayName(t));
		add(searchList);

		addWindowFocusListener(new WindowFocusListener() {

			@Override
			public void windowGainedFocus(WindowEvent e) {
				// don't care
			}

			@Override
			public void windowLostFocus(WindowEvent e) {
				panel.tabListFocusLost();
			}

		});

		KeyAdapter keyListener = new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				int keyCode = e.getKeyCode();
				switch (keyCode) {
					case KeyEvent.VK_LEFT:
						panel.highlightFromTabList(false);
						break;
					case KeyEvent.VK_RIGHT:
						panel.highlightFromTabList(true);
						break;
				}
			}
		};
		installKeyListener(this, keyListener);
		pack();
		positionRelativeTo(positioningComponent);
	}

	void close() {
		setVisible(false);
		dispose();
	}

	private SearchListModel<T> createTabListModel() {
		DefaultSearchListModel<T> model = new DefaultSearchListModel<T>();

		List<T> visibleValues = panel.getVisibleTabs();

		model.add(HIDDEN, panel.getHiddenTabs());
		model.add(VISIBLE, visibleValues);

		return model;
	}

	private void positionRelativeTo(JComponent component) {

		Rectangle bounds = getBounds();

		// no label implies we are launched from a keyboard event
		if (component == null) {

			Point centerPoint = WindowUtilities.centerOnComponent(getParent(), this);
			bounds.setLocation(centerPoint);
			WindowUtilities.ensureEntirelyOnScreen(getParent(), bounds);
			setBounds(bounds);
			return;
		}

		// show the window just below the label that launched it
		Point p = component.getLocationOnScreen();
		int x = p.x;
		int y = p.y + component.getHeight() + 3;
		bounds.setLocation(x, y);

		// fixes problem where popup gets clipped when going across screens
		WindowUtilities.ensureOnScreen(component, bounds);
		setBounds(bounds);
	}

	private class TabListRenderer extends GListCellRenderer<SearchListEntry<T>> {

		public TabListRenderer() {
			setShouldAlternateRowBackgroundColors(false);
		}

		@Override
		protected String getItemText(SearchListEntry<T> value) {
			return panel.getDisplayName(value.value());
		}

		@Override
		public Component getListCellRendererComponent(JList<? extends SearchListEntry<T>> list,
				SearchListEntry<T> value, int index, boolean isSelected, boolean hasFocus) {
			super.getListCellRendererComponent(list, value, index, isSelected, hasFocus);

			if (value.category().equals(HIDDEN)) {
				setBold();
			}
			return this;
		}

	}

	private void installKeyListener(Container c, KeyListener listener) {

		c.addKeyListener(listener);
		Component[] children = c.getComponents();
		for (Component element : children) {
			if (element instanceof Container) {
				installKeyListener((Container) element, listener);
			}
			else {
				element.addKeyListener(listener);
			}
		}
	}

}
