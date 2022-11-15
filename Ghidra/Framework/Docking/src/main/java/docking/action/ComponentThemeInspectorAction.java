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
package docking.action;

import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import javax.swing.tree.TreeCellRenderer;
import javax.swing.tree.TreePath;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.DockingWindowManager;
import generic.util.action.ReservedKeyBindings;
import ghidra.util.Msg;

public class ComponentThemeInspectorAction extends DockingAction {

	public ComponentThemeInspectorAction() {
		super("Component Theme Inspector", DockingWindowManager.DOCKING_WINDOWS_OWNER, false);
		createReservedKeyBinding(ReservedKeyBindings.COMPONENT_THEME_INFO_KEY);

		// System action; no help needed
		DockingWindowManager.getHelpService().excludeFromHelp(this);
	}

	private Object getMouseOverObject() {

		PointerInfo pointerInfo = MouseInfo.getPointerInfo();
		Point mouseLocation = pointerInfo.getLocation();
		Object lastObject = DockingWindowManager.getMouseOverObject();

		if (!(lastObject instanceof Component)) {
			return lastObject;
		}

		Component c = (Component) lastObject;
		Window w;
		if (c instanceof Window) {
			w = (Window) c;
		}
		else {
			w = SwingUtilities.windowForComponent(c);
		}

		if (w != null) {

			SwingUtilities.convertPointFromScreen(mouseLocation, w);
			Component deepestComponent =
				SwingUtilities.getDeepestComponentAt(w, mouseLocation.x, mouseLocation.y);
			if (deepestComponent != null) {
				return deepestComponent;
			}
		}

		return lastObject;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		Object object = getMouseOverObject();
		if (!(object instanceof Component)) {
			Msg.debug(this, "Mouse not over a component: " + object);
			return;
		}

		Entry entry = null;
		Component component = (Component) object;
		List<Entry> tree = new ArrayList<>();
		while (component != null) {

			Entry next;
			if (component instanceof JTable) {
				next = new TableEntry((JTable) component);
			}
			else if (component instanceof JTree) {
				next = new TreeEntry((JTree) component);
			}
			else {
				next = new Entry(component);
			}

			if (entry != null) {
				entry.parent = next;
			}
			entry = next;

			tree.add(entry);
			component = component.getParent();
		}

		Collections.reverse(tree);

		StringBuilder buffy = new StringBuilder("\n");
		for (int i = 0; i < tree.size() - 1; i++) {
			Entry e = tree.get(i);
			e.toString(buffy, i + 1); // +1 to start printing at 1, as an ordinal
		}

		buffy.append('\n');
		Entry hoveredEntry = tree.get(tree.size() - 1);
		hoveredEntry.toString(buffy, 0); // no indent for the hovered item so it is easy to see
		buffy.append('\n');
		Msg.debug(this, buffy);
	}

	private void print(StringBuilder buffy, Component component, int indent) {

		Color bg = component.getBackground();
		Color fg = component.getForeground();
		String id;
		String clazz = component.getClass().getSimpleName();
		if (clazz.isEmpty()) {
			clazz = component.getClass().getName();
		}
		String name = component.getName();
		if (name == null) {
			id = clazz;
		}
		else {
			id = clazz + "; name = " + name;
		}

		String indentMarker = "";
		String spacer = "";
		if (indent > 0) {
			indentMarker = Integer.toString(indent) + ") ";

			String asString = Integer.toString(indent);
			int length = asString.length();
			spacer = StringUtils.repeat(' ', length + 2); // +2 for the text ") "
		}
		else {
			// no indent; custom spacing of attributes
			spacer = "\t";
		}

		String tabs = '\n' + StringUtils.repeat(' ', (indent * 3));
		buffy.append(tabs)
				.append(indentMarker)
				.append(id)
				.append(tabs)
				.append(spacer)
				.append("bg: ")
				.append(bg)
				.append(tabs)
				.append(spacer)
				.append("fg: ")
				.append(fg)
				.append('\n');
	}

	private void debugComponent(Component component) {
		// stub for debugging
	}

	private void debugTable(TableCellRenderer renderer, Component component,
			Component rendererComponent) {
		// stub for debugging
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	private class Entry {

		private Entry parent;
		protected Component component;
		protected Point mouseLocation;

		Entry(Component component) {
			this.component = component;

			PointerInfo pointerInfo = MouseInfo.getPointerInfo();
			mouseLocation = pointerInfo.getLocation();
			SwingUtilities.convertPointFromScreen(mouseLocation, component);
		}

		public void toString(StringBuilder buffy, int indent) {
			debugComponent(component);
			print(buffy, component, indent);
		}

		protected boolean isLeaf(int indent) {
			return indent == 0;
		}
	}

	private class TableEntry extends Entry {
		private JTable table;

		TableEntry(JTable table) {
			super(table);
			this.table = table;
		}

		@Override
		public void toString(StringBuilder buffy, int indent) {
			print(buffy, component, indent);

			if (!isLeaf(indent)) {
				return;
			}

			// print extra data for the leaf component, as that is the hovered component
			int row = table.rowAtPoint(mouseLocation);
			int col = table.columnAtPoint(mouseLocation);

			if (row != -1 && col != -1) {
				TableCellRenderer renderer = table.getCellRenderer(row, col);
				Component rendererComponent = table.prepareRenderer(renderer, row, col);
				debugTable(renderer, component, rendererComponent);

				print(buffy, rendererComponent, indent);
			}
		}
	}

	private class TreeEntry extends Entry {
		private JTree tree;

		TreeEntry(JTree tree) {
			super(tree);
			this.tree = tree;
		}

		@Override
		public void toString(StringBuilder buffy, int indent) {
			print(buffy, component, indent);

			if (!isLeaf(indent)) {
				return;
			}

			// print extra data for the leaf component, as that is the hovered component
			TreeCellRenderer renderer = tree.getCellRenderer();
			int row = tree.getClosestRowForLocation(mouseLocation.x, mouseLocation.y);

			if (row != -1) {
				TreePath path = tree.getPathForRow(row);
				Object pathValue = path.getLastPathComponent();
				Component rendererComponent =
					renderer.getTreeCellRendererComponent(tree, pathValue, tree.isRowSelected(row),
						tree.isExpanded(row), tree.getModel().isLeaf(pathValue), row,
						true);

				print(buffy, rendererComponent, indent);
			}
		}

	}
}
