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

import docking.widgets.OptionDialog;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;

public class RetypeStructFieldTask extends RetypeFieldTask {

	private DataTypeComponent component;
	private int offset;
	private boolean disablePacking;

	public RetypeStructFieldTask(PluginTool tool, Program program, DecompilerProvider provider,
			ClangToken token, Composite composite) {
		super(tool, program, provider, token, composite);
		disablePacking = false;
	}

	@Override
	public String getTransactionName() {
		return "Retype Structure Field";
	}

	@Override
	public boolean isValidBefore() {
		if (!(composite instanceof Structure)) {
			errorMsg = "Could not identify structure at cursor";
			return false;
		}

		Structure struct = (Structure) composite;
		offset = ((ClangFieldToken) tokenAtCursor).getOffset();
		if (offset < 0 || offset >= struct.getLength()) {
			errorMsg = "Bad offset (" + offset + ") specified";
			return false;
		}

		// get original component and datatype - structure may be packed so an offset which
		// corresponds to padding byte may return null
		component = struct.getComponentContaining(offset);
		if (component != null && component.getOffset() != offset) {
			errorMsg = "Offset does not correspond to start of field";
			return false;
		}

		oldType = component != null ? component.getDataType() : DataType.DEFAULT;
		if (oldType instanceof BitFieldDataType) {
			errorMsg = "Retype of defined bit-field is not supported.";
			return false;
		}
		return true;
	}

	@Override
	public boolean isValidAfter() {
		int newDtLength = newType.getLength();
		// check for permitted datatype
		if (newType instanceof FactoryDataType || newDtLength <= 0) {
			errorMsg = "Field of type '" + newType.getName() + "' - is not allowed.";
			return false;
		}
		if (DataTypeComponent.usesZeroLengthComponent(newType)) {
			errorMsg = "Zero-length component is not allowed.";
			return false;
		}
		if (oldType == DataType.DEFAULT || newDtLength == oldType.getLength()) {
			return true;
		}

		// check for datatype fit
		int nextOffset;
		if (component == null) {
			nextOffset = offset + 1; // assume padding offset within packed structure
		}
		else {
			nextOffset = component.getEndOffset() + 1;
		}
		int available = nextOffset - offset;
		if (newDtLength > available) {
			Structure struct = (Structure) composite;
			DataTypeComponent nextComp = struct.getDefinedComponentAtOrAfterOffset(nextOffset);
			int endOffset = nextComp == null ? struct.getLength() : nextComp.getOffset();
			available += endOffset - nextOffset;
			if (newDtLength > available) {
				errorMsg = "Datatype will not fit";
				return false;
			}
		}
		if (!verifyPacking()) {
			return false;
		}

		return true;
	}

	@Override
	public void commit() throws IllegalArgumentException {
		Structure struct = (Structure) composite;

		String fieldName = null;
		String comment = null;
		if (component != null) {
			fieldName = component.getFieldName();
			comment = component.getComment();
		}

		// we cannot replace a default type, since it is not a real data type
		if (oldType != DataType.DEFAULT && newType.getLength() == oldType.getLength()) {
			// Perform simple 1-for-1 component replacement. This allows to avoid unpack in
			// some cases.  Assume component is not null since we have a non-default type.
			struct.replace(component.getOrdinal(), newType, -1, fieldName, comment);
			return;
		}

		if (disablePacking) {	// User has decided to disable packing for the structure
			// alignment is maintained for struct since we do not know the impact if we change it
			int alignment = struct.getAlignment();
			struct.setPackingEnabled(false);
			struct.setExplicitMinimumAlignment(alignment); // preserve previous alignment			
		}

		// The replaceAtOffset will only replace component containing offset plus any
		// subsequent DEFAULT components available. Space check is performed prior to any
		// clearing. Zero-length components at offset will be ignored.
		struct.replaceAtOffset(offset, newType, -1, fieldName, comment);
	}

	private boolean verifyPacking() {
		Structure struct = (Structure) composite;
		if (!struct.isPackingEnabled()) {
			return true;
		}

		if (isAlignmentMaintained()) {
			return true;
		}

		int choice = OptionDialog.showOptionDialogWithCancelAsDefaultButton(null,
			"Disable Structure Packing",
			"Containing structure currently has packing enabled.  Packing will be " +
				"disabled if you continue.",
			"Continue", OptionDialog.WARNING_MESSAGE);
		if (choice != OptionDialog.OPTION_ONE) {
			return false;
		}
		disablePacking = true;
		return true;
	}

	private boolean isAlignmentMaintained() {
		if (component == null) {
			return false;
		}
		int align = component.getDataType().getAlignment();
		if (align != newType.getAlignment()) {
			return false;
		}
		return (offset % align) == 0;
	}
}
