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

import java.util.ArrayList;

import docking.action.MenuData;
import docking.widgets.OkDialog;
import docking.widgets.OptionDialog;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class ForceUnionAction extends AbstractDecompilerAction {
	private Varnode accessVn;		// The Varnode being accessed with a union data-type
	private PcodeOp accessOp;		// PcodeOp accessing the union
	private int accessSlot;			// Slot containing the union variable (-1 for output >=0 for input)
	private int fieldNumber;		// The field (number) selected by the user to force
	private Union unionDt;			// The union data-type
	private DataType parentDt;		// The data-type associated with accessVn
	private Address pcAddr;			// Address at which field extraction takes place

	public ForceUnionAction() {
		super("Force Union Field");
//		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionRenameField"));
		setPopupMenuData(new MenuData(new String[] { "Force Field" }, "Decompile"));
//		setKeyBindingData(new KeyBindingData(KeyEvent.VK_L, 0));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (!(tokenAtCursor instanceof ClangFieldToken)) {
			return false;
		}
		Composite composite = getCompositeDataType(tokenAtCursor);
		return (composite instanceof Union);
	}

	private DataType typeIsUnionRelated(Varnode vn) {
		if (vn == null) {
			return null;
		}
		HighVariable high = vn.getHigh();
		if (high == null) {
			return null;
		}
		DataType dt = high.getDataType();
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		DataType innerType = dt;
		if (innerType instanceof Pointer) {
			innerType = ((Pointer) innerType).getDataType();
		}
		if (innerType == unionDt) {
			return dt;
		}
		// Its possible the varnode is a truncated symbol
		dt = high.getSymbol().getDataType();
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		return (dt == unionDt) ? dt : null;
	}

	private void determineFacet(ClangToken tokenAtCursor) {
		accessOp = tokenAtCursor.getPcodeOp();
		int opcode = accessOp.getOpcode();
		if (opcode == PcodeOp.PTRSUB) {
			parentDt = typeIsUnionRelated(accessOp.getInput(0));
			if (accessOp.getInput(1).getOffset() == 0) {	// Artificial op
				accessVn = accessOp.getOutput();
				accessOp = accessVn.getLoneDescend();
				if (accessOp == null) {
					return;
				}
				accessSlot = accessOp.getSlot(accessVn);
			}
			else {
				accessVn = accessOp.getInput(0);
				accessSlot = 0;
			}
		}
		else {
			for (accessSlot = 0; accessSlot < accessOp.getNumInputs(); ++accessSlot) {
				accessVn = accessOp.getInput(accessSlot);
				parentDt = typeIsUnionRelated(accessVn);
				if (parentDt != null) {
					break;
				}
			}
			if (accessSlot >= accessOp.getNumInputs()) {
				accessSlot = -1;
				accessVn = accessOp.getOutput();
				parentDt = typeIsUnionRelated(accessVn);
				if (parentDt == null) {
					accessOp = null;
					return;		// Give up, could not find type associated with field
				}
			}
			if (opcode == PcodeOp.SUBPIECE && accessSlot == 0 && !(parentDt instanceof Pointer)) {
				// SUBPIECE acts directly as resolution operator
				// Choose field based on output varnode, even though it isn't the union data-type
				accessSlot = -1;
				accessVn = accessOp.getOutput();
			}
		}
	}

	private String[] buildFieldOptions(ArrayList<String> allFields, int size) {
		DataTypeComponent[] components = unionDt.getDefinedComponents();
		ArrayList<String> res = new ArrayList<>();
		allFields.add("(no field)");
		if (size == 0 || unionDt.getLength() == size) {
			res.add("(no field)");
		}
		for (DataTypeComponent component : components) {
			String nm = component.getFieldName();
			allFields.add(nm);
			if (size == 0 || component.getDataType().getLength() == size) {
				res.add(nm);
			}
		}
		String[] resArray = new String[res.size()];
		res.toArray(resArray);
		return resArray;
	}

	private static int findStringIndex(ArrayList<String> list, String value) {
		for (int i = 0; i < list.size(); ++i) {
			if (list.get(i).equals(value)) {
				return i;
			}
		}
		return -1;
	}

	private boolean selectFieldNumber(String defaultFieldName) {
		int size = 0;
		if (!(parentDt instanceof Pointer)) {
			size = accessVn.getSize();
		}
		ArrayList<String> allFields = new ArrayList<>();
		String[] choices = buildFieldOptions(allFields, size);
		if (choices.length < 2) {	// If only one field fits the Varnode
			OkDialog.show("No Field Choices", "Only one field fits the selected variable");
			return false;
		}
		int currentChoice = findStringIndex(allFields, defaultFieldName);
		if (currentChoice < 0) {
			defaultFieldName = null;
		}
		String userChoice = OptionDialog.showInputChoiceDialog(null,
			"Select Field for " + unionDt.getName(), "Field for " + unionDt.getName() + ": ",
			choices, defaultFieldName, OptionDialog.PLAIN_MESSAGE);
		if (userChoice == null) {
			return false;		// User cancelled when making the choice
		}
		fieldNumber = findStringIndex(allFields, userChoice);
		if (fieldNumber < 0 || fieldNumber == currentChoice) {
			return false;	// User chose original value or something not in list, treat as cancel
		}
		fieldNumber -= 1;	// Convert choice index to field number
		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Program program = context.getProgram();
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		HighFunction highFunction = context.getHighFunction();
		unionDt = (Union) getCompositeDataType(tokenAtCursor);
		determineFacet(tokenAtCursor);
		if (accessOp == null || accessVn == null) {
			Msg.showError(this, null, "Force Union failed", "Could not recover p-code op");
			return;
		}
		if (!selectFieldNumber(tokenAtCursor.getText())) {
			return;		// User cancelled or no options to choose from
		}
		Function function = highFunction.getFunction();
		DynamicHash dhash = new DynamicHash(accessOp, accessSlot, highFunction);
		pcAddr = dhash.getAddress();
		if (pcAddr == Address.NO_ADDRESS) {
			Msg.showError(this, null, "Force Union failed", "Unable to find a unique hash");
		}
		int transaction = program.startTransaction("Force Union");
		try {
			HighFunctionDBUtil.writeUnionFacet(function, parentDt, fieldNumber, pcAddr,
				dhash.getHash(), SourceType.USER_DEFINED);
		}
		catch (DuplicateNameException e) {
			Msg.showError(this, null, "Force Union failed", e.getMessage());
		}
		catch (InvalidInputException e) {
			Msg.showError(this, null, "Force Union failed", e.getMessage());
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

}
