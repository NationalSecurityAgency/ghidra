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
package ghidra.app.plugin.core.byteviewer;

import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;

/**
 * Creates a container for holding multiple horizontally aligned components and provides
 * a {@link JTableHeader} that can be used to interactively reorder and resize the 
 * components that are managed by this container.
 */
public class InteractivePanelManager {
	private JPanel mainPanel;
	private JTableHeader header;
	private TableColumnModel columnModel;
	private int separatorWidth;

	public InteractivePanelManager() {
		JTable table = new JTable();
		header = table.getTableHeader();
		columnModel = header.getColumnModel();
		separatorWidth = (new JSeparator(SwingConstants.VERTICAL)).getPreferredSize().width;
		mainPanel = new JPanel(new HeaderLayoutManager());
		columnModel.addColumnModelListener(new PanelManagerColumnModelListener());
	}

	/**
	 * Sets the font for the header component.
	 * @param font the font to be used to display view names in the header
	 */
	public void setHeaderFont(Font font) {
		header.setFont(font);
	}

	/**
	 * Adds a component and it's name to the set of managed components.
	 * @param name the name to display in its column header.
	 * @param component the component to add
	 */
	public void addComponent(String name, JComponent component) {
		TableColumn column = new TableColumn();
		column.addPropertyChangeListener(e -> columnPropertyChanged(e));
		column.setHeaderValue(new ComponentData(name, component));
		column.setPreferredWidth(component.getPreferredSize().width + separatorWidth);
		column.setWidth(component.getPreferredSize().width);
		columnModel.addColumn(column);
		mainPanel.add(component);
		mainPanel.add(new JSeparator(SwingConstants.VERTICAL));
	}

	/**
	 * Returns a list of the components being managed.
	 * @return a list of the components being managed.
	 */
	public List<JComponent> getComponents() {
		List<JComponent> components = new ArrayList<>();
		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			components.add(((ComponentData) column.getHeaderValue()).component);
		}
		return components;
	}

	/**
	 * Sets the name for a component
	 * @param component the component for which to change its associated name
	 * @param newName the new name for the component
	 */
	public void setName(JComponent component, String newName) {
		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			ComponentData componentData = (ComponentData) column.getHeaderValue();
			if (componentData.component() == component) {
				column.setHeaderValue(new ComponentData(newName, component));
				break;
			}
		}
	}

	/**
	 * Removes the given component from being managed.
	 * @param component the component to be removed
	 */
	public void removeComponent(JComponent component) {

		int componentCount = mainPanel.getComponentCount();
		for (int i = 0; i < componentCount; i++) {
			if (mainPanel.getComponent(i) == component) {
				mainPanel.remove(i);
				mainPanel.remove(i);	// also remove the JSeparator the follows it
				break;
			}
		}
		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			if (((ComponentData) column.getHeaderValue()).component == component) {
				columnModel.removeColumn(column);
				break;
			}
		}
	}

	/**
	 * Returns the mainPanel containing the horizontally laid components.
	 * @return the mainPanel containing the horizontally laid components
	 */
	public JComponent getMainPanel() {
		return mainPanel;
	}

	/**
	 * Returns the {@link JTableHeader} component that can be  used to reorder and resize
	 * the components
	 * @return the JTableHeader for managing the order and size of the components
	 */
	public JComponent getColumnHeader() {
		return header;
	}

	/**
	 * Returns the current width of the component with the given name.
	 * @param viewName the name of the component for which to get its width
	 * @return the current width of the component with the given name
	 */
	public int getColumnWidth(String viewName) {
		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			ComponentData data = (ComponentData) column.getHeaderValue();
			if (data.name().equals(viewName)) {
				return column.getWidth();
			}
		}
		return 0;
	}

	/**
	 * Sets the width of the named component.
	 * @param viewName the name of the component to resize
	 * @param width the new width for the given component
	 */
	public void setColumnWidth(String viewName, int width) {
		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			ComponentData data = (ComponentData) column.getHeaderValue();
			if (data.name().equals(viewName)) {
				column.setWidth(width);
				return;
			}
		}
	}

	/**
	 * Resets the named component back to its preferred size.
	 * @param viewName the name of the component to restore to its preferred size
	 */
	public void resetColumnWidthToPreferredWidth(String viewName) {
		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			ComponentData data = (ComponentData) column.getHeaderValue();
			if (data.name().equals(viewName)) {
				column.setWidth(data.component().getPreferredSize().width);
				return;
			}
		}
	}

	private void columnPropertyChanged(PropertyChangeEvent e) {
		if ("width".equals(e.getPropertyName())) {
			TableColumn column = (TableColumn) e.getSource();
			column.setPreferredWidth((int) e.getNewValue());
			update();
		}
	}

	private void update() {
		mainPanel.invalidate();
		Container parent = mainPanel.getParent();
		if (parent != null) {
			parent.validate();
			parent.repaint();
		}
	}

	private class HeaderLayoutManager implements LayoutManager {

		@Override
		public void addLayoutComponent(String name, Component comp) {
			// don't care
		}

		@Override
		public void removeLayoutComponent(Component comp) {
			// don't care
		}

		@Override
		public Dimension preferredLayoutSize(Container parent) {
			Insets insets = parent.getInsets();
			int n = parent.getComponentCount();
			int height = 0;
			int width = columnModel.getTotalColumnWidth();

			for (int i = 0; i < n; i++) {
				Component c = parent.getComponent(i);
				Dimension d = c.getPreferredSize();
				height = Math.max(height, d.height);
			}
			return new Dimension(width + insets.left + insets.right,
				height + insets.top + insets.bottom);

		}

		@Override
		public Dimension minimumLayoutSize(Container parent) {
			return preferredLayoutSize(parent);
		}

		@Override
		public void layoutContainer(Container parent) {
			int n = parent.getComponentCount();
			Dimension d = parent.getSize();
			Insets insets = parent.getInsets();
			int height = d.height - insets.top - insets.bottom;

			int x = insets.left;
			int y = insets.top;
			for (int i = 0; i < n; i++) {
				// even components are the actual managed components, odd components are JSeparators
				if (i % 2 == 0) {
					TableColumn column = columnModel.getColumn(i / 2);
					ComponentData componentData = (ComponentData) column.getHeaderValue();
					JComponent c = componentData.component();
					int width = column.getWidth() - separatorWidth;
					c.setBounds(x, y, width, height);
					x += width;
				}
				else {
					Component c = parent.getComponent(i);
					d = c.getPreferredSize();
					c.setBounds(x, y, d.width, height);
					x += d.width;
				}
			}
		}

	}

	private class PanelManagerColumnModelListener implements TableColumnModelListener {

		@Override
		public void columnAdded(TableColumnModelEvent e) {
			update();
		}

		@Override
		public void columnRemoved(TableColumnModelEvent e) {
			update();
		}

		@Override
		public void columnMoved(TableColumnModelEvent e) {
			update();
		}

		@Override
		public void columnMarginChanged(ChangeEvent e) {
			// ignore
		}

		@Override
		public void columnSelectionChanged(ListSelectionEvent e) {
			// ignore
		}

	}

	record ComponentData(String name, JComponent component) {
		@Override
		public String toString() {
			return name;
		}
	}

}
