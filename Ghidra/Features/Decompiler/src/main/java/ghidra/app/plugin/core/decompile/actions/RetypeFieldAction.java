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
package ghidra.app.plugin.core.decompile.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.*;

/**
 * Action triggered from a specific token in the decompiler window to change the data-type of
 * a field within a structure data-type. The field must already exist, except in the case of a
 * completely undefined structure. The data-type of the field is changed according to the user
 * selection.  If the size of the selected data-type is bigger, this can trigger other fields in
 * the structure to be removed and may change the size of the structure.  The modified data-type
 * is permanently committed to the program's database.
 */
public class RetypeFieldAction extends AbstractDecompilerAction {

	public RetypeFieldAction() {
		super("Retype Field");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRetypeField"));
		setPopupMenuData(new MenuData(new String[] { "Retype Field" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, InputEvent.CTRL_DOWN_MASK));
	}

	/**
	 * Return the index of the last component that would be overwritten by a new datatype, if we started overwriting
	 * with at a specific component. All components, except the first, must be undefined datatypes or we return -1
	 * @param struct is the structure we are testing
	 * @param comp is the starting component to overwrite
	 * @param newtype is the datatype to overwrite with
	 * @return the index of the last component overwritten or -1
	 */
	private static int getEndComponentIndex(Structure struct, DataTypeComponent comp,
			DataType newtype) {
		int newlen = newtype.getLength();
		if (newlen <= 0) {
			return -1; // Don't support variable length types
		}
		DataType curtype = comp.getDataType();
		newlen -= curtype.getLength();
		int index = comp.getOrdinal();
		while (newlen > 0) {
			index += 1;
			if (index >= struct.getNumComponents()) {
				return -1; // Not enough space in the structure
			}
			comp = struct.getComponent(index);
//			String nm = comp.getFieldName();
//			if ((nm !=null)&&(nm.length()!=0))
//				return -1;
			curtype = comp.getDataType();
//			if (!Undefined.isUndefined(curtype))
//				return -1;						// Overlaps non-undefined datatype
			if (curtype != DataType.DEFAULT) {
				return -1; // Only allow overwrite of placeholder components
			}
			newlen -= curtype.getLength();
		}
		return index;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		if (tokenAtCursor instanceof ClangFieldToken) {
			DataType dt = getStructDataType(tokenAtCursor);
			return (dt != null);
		}
		return false;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Program program = context.getProgram();
		PluginTool tool = context.getTool();
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		DataTypeManager dataTypeManager = program.getDataTypeManager();

		DataType dataType = null;
		Structure struct = getStructDataType(tokenAtCursor);
		int offset = ((ClangFieldToken) tokenAtCursor).getOffset();
		if (struct == null) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Failed to re-type structure");
			return;
		}
		if (offset < 0 || offset >= struct.getLength()) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Failed to re-type structure: " + struct.getName());
			return;
		}
		DataTypeComponent comp = struct.getComponentAt(offset);
		if (comp == null) {
			dataType = chooseDataType(tool, program, DataType.DEFAULT);
		}
		else {
			dataType = chooseDataType(tool, program, comp.getDataType());
		}

		if (dataType == null) {
			return;
		}
		boolean successfulMod = false;
		if (comp == null) {
			if (!struct.isNotYetDefined()) {
				Msg.showError(this, tool.getToolFrame(), "Retype Failed",
					"Could not find component of '" + struct.getName() + "' to retype");
				return;
			}
			// note if we reach here the offset must be zero, so assume we are inserting newtype
			int transaction = program.startTransaction("Retype Structure Field");
			try {
				// Make sure datatype is using the program's data organization before testing fit
				if (dataType.getDataTypeManager() != dataTypeManager) {
					dataType = dataTypeManager.resolve(dataType, null);
				}
				struct.insert(0, dataType);
				successfulMod = true;
			}
			finally {
				program.endTransaction(transaction, successfulMod);
			}
			return;
		}
		int transaction = program.startTransaction("Retype Structure Field");
		try {
			// Make sure datatype is using the program's data organization before testing fit
			if (dataType.getDataTypeManager() != dataTypeManager) {
				dataType = dataTypeManager.resolve(dataType, null);
			}
			int startind = comp.getOrdinal();
			int endind = getEndComponentIndex(struct, comp, dataType);
			if (endind < 0) {
				Msg.showError(this, tool.getToolFrame(), "Retype Failed",
					"Failed to re-type structure '" + struct.getName() + "': Datatype did not fit");
				return;
			}
			for (int i = endind; i > startind; --i) { // Clear all but first field
				struct.clearComponent(i);
			}
			struct.replaceAtOffset(comp.getOffset(), dataType, dataType.getLength(),
				comp.getFieldName(), comp.getComment());
			successfulMod = true;
		}
		finally {
			program.endTransaction(transaction, successfulMod);
		}
	}
}
