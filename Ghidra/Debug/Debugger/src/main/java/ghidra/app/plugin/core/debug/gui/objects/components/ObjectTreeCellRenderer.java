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
package ghidra.app.plugin.core.debug.gui.objects.components;

import java.awt.*;
import java.util.Map;

import javax.swing.JTree;
import javax.swing.tree.TreePath;

import docking.widgets.tree.support.GTreeRenderer;
import generic.theme.GColor;
import generic.theme.Gui;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetObject;

class ObjectTreeCellRenderer extends GTreeRenderer {

	private static final Color COLOR_FOREGROUND_SELECTION = new GColor("color.fg.tree.selected");
	private static final String FONT_ID = "font.debugger.object.tree.renderer";

	private final DebuggerObjectsProvider provider;

	public ObjectTreeCellRenderer(DebuggerObjectsProvider provider) {
		this.provider = provider;
	}

	@Override
	public Component getTreeCellRendererComponent(JTree t, Object value, boolean sel, boolean exp,
			boolean leaf, int row, boolean focus) {
		Component component =
			super.getTreeCellRendererComponent(t, value, sel, exp, leaf, row, focus);
		if (value instanceof ObjectNode node) {
			ObjectContainer container = node.getContainer();
			setText(container.getDecoratedName());
			component.setForeground(provider.COLOR_FOREGROUND);
			TargetObject targetObject = container.getTargetObject();
			if (container.isSubscribed()) {
				Color color = provider.COLOR_FOREGROUND_SUBSCRIBED;
				if (!color.equals(getTextNonSelectionColor())) {
					component.setForeground(color);
				}
			}
			if (targetObject != null) {
				Map<String, ?> attrs = targetObject.getCachedAttributes();
				String kind = (String) attrs.get(TargetObject.KIND_ATTRIBUTE_NAME);
				if (kind != null && !kind.equals("")) {
					if (kind.equals("OBJECT_INTRINSIC")) {
						container.subscribe();
					}
					setColor(component, kind);
				}
			}
			if (!node.isVisible() && !provider.isHideIntrinsics()) {
				component.setForeground(provider.COLOR_FOREGROUND_INVISIBLE);
			}
			if (container.getTargetObject() instanceof TargetExecutionStateful) {
				TargetExecutionStateful stateful = (TargetExecutionStateful) targetObject;
				if (stateful.getExecutionState().equals(TargetExecutionState.TERMINATED)) {
					component.setForeground(provider.COLOR_FOREGROUND_INVALIDATED);
				}
			}
			if (container.isLink()) {
				component.setForeground(provider.COLOR_FOREGROUND_LINK);
			}
			if (container.isModified()) {
				component.setForeground(provider.COLOR_FOREGROUND_MODIFIED);
			}
			TreePath path = t.getSelectionPath();
			if (path != null) {
				Object last = path.getLastPathComponent();
				if (last instanceof ObjectNode) {
					ObjectContainer selection = ((ObjectNode) last).getContainer();
					if (container.equals(selection)) {
						component.setForeground(COLOR_FOREGROUND_SELECTION);
					}
				}
			}
			Font font = Gui.getFont(FONT_ID);
			if (container.isFocused()) {
				font = font.deriveFont(Font.BOLD);
			}
			component.setFont(font);
		}
		return component;
	}

	private void setColor(Component component, String kind) {
		switch (kind) {
			case "OBJECT_PROPERTY_ACCESSOR":
				component.setForeground(provider.COLOR_FOREGROUND);
				break;
			case "OBJECT_INTRINSIC":
				component.setForeground(provider.COLOR_FOREGROUND_INTRINSIC);
				break;
			case "OBJECT_TARGET_OBJECT":
				component.setForeground(provider.COLOR_FOREGROUND_TARGET);
				break;
			case "OBJECT_ERROR":
				component.setForeground(provider.COLOR_FOREGROUND_ERROR);
				break;
		}
	}

	protected Component highlight(Component component) {
		return component;
	}
}
