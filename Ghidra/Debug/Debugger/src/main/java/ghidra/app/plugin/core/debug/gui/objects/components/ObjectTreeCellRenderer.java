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
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetObject;

// TODO: In the new scheme, I'm not sure this is applicable anymore.
class ObjectTreeCellRenderer extends GTreeRenderer {

	private final DebuggerObjectsProvider provider;
	private Font defaultFont = new Font("Tahoma", Font.PLAIN, 11);
	private Font unsubscribedFont = new Font("Tahoma", Font.ITALIC, 11);

	/**
	 * @param provider
	 */
	public ObjectTreeCellRenderer(DebuggerObjectsProvider provider) {
		this.provider = provider;
	}

	@Override
	public Component getTreeCellRendererComponent(JTree t, Object value, boolean sel, boolean exp,
			boolean leaf, int row, boolean focus) {
		Component component =
			super.getTreeCellRendererComponent(t, value, sel, exp, leaf, row, focus);
		if (value instanceof ObjectNode) {
			ObjectNode node = (ObjectNode) value;
			ObjectContainer container = node.getContainer();
			setText(container.getDecoratedName());
			component.setForeground(
				provider.getColor(DebuggerObjectsProvider.OPTION_NAME_DEFAULT_FOREGROUND_COLOR));
			TargetObject targetObject = container.getTargetObject();
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
				component.setForeground(provider
						.getColor(DebuggerObjectsProvider.OPTION_NAME_INVISIBLE_FOREGROUND_COLOR));
			}
			if (container.getTargetObject() instanceof TargetExecutionStateful) {
				TargetExecutionStateful stateful = (TargetExecutionStateful) targetObject;
				if (stateful.getExecutionState().equals(TargetExecutionState.TERMINATED)) {
					component.setForeground(provider
							.getColor(
								DebuggerObjectsProvider.OPTION_NAME_INVALIDATED_FOREGROUND_COLOR));
				}
			}
			if (container.isLink()) {
				component.setForeground(
					provider.getColor(DebuggerObjectsProvider.OPTION_NAME_LINK_FOREGROUND_COLOR));
			}
			if (container.isModified()) {
				component.setForeground(provider
						.getColor(DebuggerObjectsProvider.OPTION_NAME_MODIFIED_FOREGROUND_COLOR));
			}
			if (container.isSubscribed()) {
				Color color = provider
						.getColor(DebuggerObjectsProvider.OPTION_NAME_SUBSCRIBED_FOREGROUND_COLOR);
				if (!color.equals(Color.BLACK)) {
					component.setForeground(color);
				}
			}
			TreePath path = t.getSelectionPath();
			if (path != null) {
				Object last = path.getLastPathComponent();
				if (last instanceof ObjectNode) {
					ObjectContainer selection = ((ObjectNode) last).getContainer();
					if (container.equals(selection)) {
						component.setForeground(Color.WHITE);
					}
				}
			}
			component.setFont(container.isSubscribed() ? defaultFont : unsubscribedFont);
		}
		return component;
	}

	private void setColor(Component component, String kind) {
		switch (kind) {
			case "OBJECT_PROPERTY_ACCESSOR":
				component.setForeground(provider
						.getColor(DebuggerObjectsProvider.OPTION_NAME_ACCESSOR_FOREGROUND_COLOR));
				break;
			case "OBJECT_INTRINSIC":
				component.setForeground(provider
						.getColor(DebuggerObjectsProvider.OPTION_NAME_INTRINSIC_FOREGROUND_COLOR));
				break;
			case "OBJECT_TARGET_OBJECT":
				component.setForeground(
					provider.getColor(DebuggerObjectsProvider.OPTION_NAME_TARGET_FOREGROUND_COLOR));
				break;
			case "OBJECT_ERROR":
				component.setForeground(
					provider.getColor(DebuggerObjectsProvider.OPTION_NAME_ERROR_FOREGROUND_COLOR));
				break;
		}
	}

	protected Component highlight(Component component) {
		return component;
	}
}
