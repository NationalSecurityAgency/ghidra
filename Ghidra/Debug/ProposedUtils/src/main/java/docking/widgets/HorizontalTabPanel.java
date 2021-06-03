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
package docking.widgets;

import java.awt.*;
import java.awt.event.ActionEvent;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.event.ChangeEvent;

// TODO: I'd like "close" buttons on the tabs, optionally.
//       For now, client must use a popup menu.
@SuppressWarnings("serial")
public class HorizontalTabPanel<T> extends JPanel {
	public static Color copyColor(Color c) {
		return new Color(c.getRGB());
	}

	public static class TabListCellRenderer<T> implements ListCellRenderer<T> {
		protected final Box hBox = Box.createHorizontalBox();
		protected final JLabel label = new JLabel();

		{
			hBox.setBorder(new BevelBorder(BevelBorder.RAISED));
			hBox.setOpaque(true);
			hBox.add(label);
		}

		protected String getText(T value) {
			return value.toString();
		}

		protected Icon getIcon(T value) {
			return null;
		}

		@Override
		public Component getListCellRendererComponent(JList<? extends T> list,
				T value, int index, boolean isSelected, boolean cellHasFocus) {
			label.setText(getText(value));
			label.setIcon(getIcon(value));

			if (isSelected) {
				//label.setForeground(list.getSelectionForeground());
				label.setForeground(copyColor(list.getSelectionForeground()));
				hBox.setBackground(list.getSelectionBackground());
			}
			else {
				label.setForeground(list.getForeground());
				hBox.setBackground(list.getBackground());
			}
			hBox.validate();
			return hBox;
		}
	}

	private final JList<T> list = new JList<>();
	private final JScrollPane scroll = new JScrollPane(list);
	private final JViewport viewport = scroll.getViewport();
	private final DefaultListModel<T> model = new DefaultListModel<>();
	private final JButton left = new JButton("<");
	private final JButton right = new JButton(">");

	{
		list.setModel(model);
		// TODO: Experiment with multiple traces in one timeline
		list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		list.setLayoutOrientation(JList.HORIZONTAL_WRAP);
		list.setVisibleRowCount(1);
		list.setCellRenderer(new TabListCellRenderer<>());
		list.setOpaque(false);

		scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
		scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		scroll.setBorder(null);

		viewport.addChangeListener(this::viewportChanged);

		left.setBorder(null);
		right.setBorder(null);
		left.setContentAreaFilled(false);
		right.setContentAreaFilled(false);
		left.setOpaque(true);
		right.setOpaque(true);
		left.addActionListener(this::leftActivated);
		right.addActionListener(this::rightActivated);
	}

	public HorizontalTabPanel() {
		super();
		setLayout(new BorderLayout());
		list.setBackground(getBackground());
		add(scroll, BorderLayout.CENTER);
		add(left, BorderLayout.WEST);
		add(right, BorderLayout.EAST);
	}

	private void viewportChanged(ChangeEvent e) {
		Dimension paneSize = getSize();
		Dimension listSize = list.getSize();
		boolean buttonsVisible = paneSize.getWidth() < listSize.getWidth();
		left.setVisible(buttonsVisible);
		right.setVisible(buttonsVisible);
	}

	/**
	 * Find the first cell which is even partially visible
	 * 
	 * @param reverse true to search from right to left
	 * @return the cell index
	 */
	private int findFirstVisible(boolean reverse) {
		int n = model.getSize();
		Rectangle vis = list.getVisibleRect();
		for (int i = reverse ? n - 1 : 0; reverse ? i >= 0 : i < n; i += reverse ? -1 : 1) {
			Rectangle b = list.getCellBounds(i, i);
			if (vis.intersects(b)) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * Find the first cell <em>after</em> a given start which is even partially occluded
	 * 
	 * @param start the starting cell index
	 * @param reverse true to search from right to left
	 * @return the cell index
	 */
	private int findNextOccluded(int start, boolean reverse) {
		if (start == -1) {
			return -1;
		}
		int n = model.getSize();
		Rectangle vis = list.getVisibleRect();
		for (int i = reverse ? start - 1 : start + 1; reverse ? i >= 0 : i < n; i +=
			reverse ? -1 : 1) {
			Rectangle b = list.getCellBounds(i, i);
			if (!vis.contains(b)) {
				return i;
			}
		}
		return -1;
	}

	private void leftActivated(ActionEvent e) {
		list.ensureIndexIsVisible(findNextOccluded(findFirstVisible(true), true));
	}

	private void rightActivated(ActionEvent e) {
		list.ensureIndexIsVisible(findNextOccluded(findFirstVisible(false), false));
	}

	public JList<T> getList() {
		return list;
	}

	public void addItem(T item) {
		model.addElement(item);
		revalidate();
	}

	public void removeItem(T item) {
		model.removeElement(item);
		revalidate();
	}

	public T getSelectedItem() {
		int index = list.getSelectedIndex();
		return index < 0 ? null : list.getModel().getElementAt(index);
	}

	public void setSelectedItem(T item) {
		// NOTE: For large lists, this could get slow
		int index = model.indexOf(item);
		if (index < 0) {
			list.clearSelection();
		}
		else {
			list.setSelectedIndex(index);
		}
	}

	public T getItem(int index) {
		return list.getModel().getElementAt(index);
	}
}
