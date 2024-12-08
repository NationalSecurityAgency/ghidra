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
package ghidra.app.plugin.core.data;

import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.FieldNameFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * Base class for comment actions to edit and delete comments.
 */
class RenameDataFieldAction extends ListingContextAction {

	private DataPlugin plugin;

	public RenameDataFieldAction(DataPlugin plugin) {
		super("Rename Data Field", plugin.getName());

		setPopupMenuData(
			new MenuData(
				new String[] { "Data", "Rename Field" }, null, "BasicData"));

		setKeyBindingData(new KeyBindingData(
			KeyEvent.VK_N, 0));

		this.plugin = plugin;
		setEnabled(true);
	}

	@Override
	protected void actionPerformed(ListingActionContext context) {
		ListingActionContext programActionContext =
			(ListingActionContext) context.getContextObject();
		PluginTool tool = plugin.getTool();
		Program program = programActionContext.getProgram();
		ProgramLocation loc = programActionContext.getLocation();
		Data data = program.getListing().getDataContaining(loc.getAddress());
		DataType type = data.getDataType();

		if (type instanceof Composite) {
			Composite comp = (Composite) type;
			int[] compPath = loc.getComponentPath();
			for (int i = 0; i < compPath.length - 1; i++) {
				DataTypeComponent subComp = comp.getComponent(compPath[i]);
				type = subComp.getDataType();
				if (type instanceof Composite) {
					comp = (Composite) type;
				}
				else {
					return;
				}
			}

			Data instance = data.getComponent(compPath);
			DataTypeComponent subComp = comp.getComponent(compPath[compPath.length - 1]);
			RenameDataFieldDialog dialog = new RenameDataFieldDialog(plugin);
			dialog.setDataComponent(program, subComp, instance.getFieldName());
			tool.showDialog(dialog);
		}
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		return (context.getLocation() instanceof FieldNameFieldLocation);
	}

}
