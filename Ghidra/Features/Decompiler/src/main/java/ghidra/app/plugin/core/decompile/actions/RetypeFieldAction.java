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
import docking.widgets.OptionDialog;
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

		Structure struct = getStructDataType(tokenAtCursor);
		int offset = ((ClangFieldToken) tokenAtCursor).getOffset();
		if (struct == null) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Failed to re-type structure");
			return;
		}
		if (offset < 0 || offset >= struct.getLength()) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Failed to re-type structure field at offset " + offset + ": " + struct.getName());
			return;
		}

		// Get original component and datatype - structure may be packed so an offset which corresponds
		// to padding byte may return null
		DataTypeComponent comp = struct.getComponentContaining(offset);
		if (comp != null && comp.getOffset() != offset) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Retype offset does not correspond to start of component");
			return;
		}
		DataType originalDataType = comp != null ? comp.getDataType() : DataType.DEFAULT;
		if (originalDataType instanceof BitFieldDataType) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Retype of defind bit-field is not supported.");
			return;
		}

		DataType dataType = chooseDataType(tool, program, originalDataType);
		if (dataType == null || dataType.isEquivalent(originalDataType)) {
			return; // cancelled
		}

		// check for permitted datatype
		if (dataType instanceof FactoryDataType || dataType.getLength() <= 0) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Retype field with \"" + dataType.getName() + "\" data type is not allowed.");
		}

		int transaction = program.startTransaction("Retype Structure Field");
		try {
			dataType = dataTypeManager.resolve(dataType, null);
			int newDtLength = dataType.getLength();

			if (DataTypeComponent.usesZeroLengthComponent(dataType)) {
				Msg.showError(this, tool.getToolFrame(), "Retype Failed", "Retype field with \"" +
					dataType.getName() + "\" zero-length component is not allowed.");
			}

			if (originalDataType != DataType.DEFAULT &&
				newDtLength == originalDataType.getLength()) {
				// Perform simple 1-for-1 component replacement - this allows to avoid unpack in some cases - assume comp is not null
				struct.replace(comp.getOrdinal(), dataType, -1);
				return;
			}

			// check for datatype fit
			String fieldName = null;
			String comment = null;
			int nextOffset;
			if (comp == null) {
				nextOffset = offset + 1; // assume padding offset within packed structure
			}
			else {
				fieldName = comp.getFieldName();
				comment = comp.getComment();
				nextOffset = comp.getEndOffset() + 1;
			}
			int available = nextOffset - offset;
			if (newDtLength > available) {
				DataTypeComponent nextComp = struct.getDefinedComponentAtOrAfterOffset(nextOffset);
				int endOffset = nextComp == null ? struct.getLength() : nextComp.getOffset();
				available += endOffset - nextOffset;
				if (newDtLength > available) {
					Msg.showError(this, tool.getToolFrame(), "Retype Failed",
						"Failed to re-type structure '" + struct.getName() +
							"': Datatype will not fit");
					return;
				}
			}

			if (struct.isPackingEnabled() && !isAlignmentMaintained(comp, dataType, offset)) {
				int choice = OptionDialog.showOptionDialogWithCancelAsDefaultButton(null,
					"Disable Structure Packing",
					"Containing structure currently has packing enabled.  Packing will be disabled if you continue.",
					"Continue", OptionDialog.WARNING_MESSAGE);
				if (choice != OptionDialog.OPTION_ONE) {
					return; // cancelled
				}
				// alignment is maintained for struct since we do not know the extent of the impact if we change it
				int alignment = struct.getAlignment();
				struct.setPackingEnabled(false);
				struct.setExplicitMinimumAlignment(alignment); // preserve previously computed alignment
			}

			// The replaceAtOffset will only replace component containing offset plus any subsequent DEFAULT
			// components available. Space check is performed prior to any clearing. Zero-length components
			// at offset will be ignored.
			struct.replaceAtOffset(offset, dataType, -1, fieldName, comment);
		}
		catch (IllegalArgumentException e) {
			Msg.showError(this, tool.getToolFrame(), "Retype Failed",
				"Failed to re-type structure: " + e.getMessage());
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private boolean isAlignmentMaintained(DataTypeComponent comp, DataType dataType, int offset) {
		if (comp == null) {
			return false;
		}
		int align = comp.getDataType().getAlignment();
		if (align != dataType.getAlignment()) {
			return false;
		}
		return (offset % align) == 0;
	}
}
