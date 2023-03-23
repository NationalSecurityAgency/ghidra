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

import java.awt.Component;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;

public class ObjectTableCellRenderer extends AbstractGhidraColumnRenderer<Object> {
	private final DebuggerObjectsProvider provider;

	public ObjectTableCellRenderer(DebuggerObjectsProvider provider) {
		this.provider = provider;
	}

	@Override
	public String getFilterString(Object t, Settings settings) {
		return t == null ? "<null>" : t.toString();
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {
		super.getTableCellRendererComponent(data);
		TargetObject focus = provider.getFocus();
		if (focus == null) {
			return this;
		}
		Object rowObject = data.getRowObject();
		TargetObject object;
		if (rowObject instanceof ObjectElementRow eRow) {
			object = eRow.getTargetObject();
		}
		else if (rowObject instanceof ObjectAttributeRow aRow) {
			object = aRow.getTargetObject();
		}
		else {
			return this;
		}
		if (PathUtils.isAncestor(object.getPath(), focus.getPath())) {
			setBold();
		}
		return this;
	}
}
