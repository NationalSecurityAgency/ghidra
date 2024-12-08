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
import ghidra.app.util.HelpTopics;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * An action to force the use of a particular field on the access of a union.
 * The user selects particular field name token in the decompiler window and is presented
 * with a list of other possible fields the access can be changed to.
 */
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
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionForceField"));
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

	/**
	 * Determine if the data-type of the given Varnode is related to the union -unionDt-
	 * The Varnode's data-type may be a typedef of, a pointer to, or a truncated form of
	 * the union.  If so the Varnode's data-type is returned, otherwise null is returned.
	 * @param vn is the given Varnode
	 * @return the data-type of the Varnode (if it is related to the union) or null
	 */
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
		else if (innerType instanceof PartialUnion) {
			innerType = ((PartialUnion) innerType).getParent();
			if (innerType instanceof TypeDef) {
				innerType = ((TypeDef) innerType).getBaseDataType();
			}
		}
		if (innerType == unionDt) {
			return dt;
		}
		// Its possible the varnode is a truncated symbol
		HighSymbol symbol = high.getSymbol();
		if (symbol == null) {
			return null;
		}
		dt = symbol.getDataType();
		if (dt instanceof TypeDef) {
			dt = ((TypeDef) dt).getBaseDataType();
		}
		return (dt == unionDt) ? dt : null;
	}

	/**
	 * Determine the particular Varnode whose union facet will be modified by this action.
	 * The field -accessVn- will be filled in with the particular Varnode. -accessOp- is set to
	 * the operation at the cursor, and -accessOp- is either an input or the output, with
	 * -accessSlot- being set either to the input slot or -1 if the Varnode is the output.
	 * Additionally -parentDt is filled in with the data-type associated with the Varnode.
	 * If the union can't be determined, -accessOp- is set to null.
	 * @param tokenAtCursor is the display token selected by the user
	 */
	private void determineFacet(ClangToken tokenAtCursor) {
		accessOp = tokenAtCursor.getPcodeOp();
		int opcode = accessOp.getOpcode();
		if (opcode == PcodeOp.PTRSUB) {
			parentDt = typeIsUnionRelated(accessOp.getInput(0));
			if (parentDt == null) {
				accessOp = null;
				return;
			}
			accessVn = accessOp.getInput(0);
			accessSlot = 0;
			if (accessOp.getInput(1).getOffset() == 0) {	// Artificial op
				do {
					Varnode tmpVn = accessOp.getOutput();
					PcodeOp tmpOp = tmpVn.getLoneDescend();
					if (tmpOp == null) {
						break;
					}
					accessOp = tmpOp;
					accessVn = tmpVn;
					accessSlot = accessOp.getSlot(accessVn);
				}
				while (accessOp.getOpcode() == PcodeOp.PTRSUB &&
					accessOp.getInput(1).getOffset() == 0);
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

	/**
	 * Build a list of all the union field names for the user to select from, when determining
	 * which data-type to force.  Two lists are produced.  The first contains every possible
	 * field name. The second list is filtered by the size and offset of the Varnode being forced.
	 * @param allFields will hold the unfiltered list of names
	 * @return the filtered list of names
	 */
	private String[] buildFieldOptions(ArrayList<String> allFields) {
		int size = accessVn.getSize();
		int startOff = 0;
		boolean exactMatch = true;
		if (parentDt instanceof Pointer) {
			size = 0;
		}
		if (parentDt instanceof PartialUnion) {
			startOff = ((PartialUnion) parentDt).getOffset();
			exactMatch = false;
		}
		int endOff = startOff + size;
		DataTypeComponent[] components = unionDt.getDefinedComponents();
		ArrayList<String> res = new ArrayList<>();
		allFields.add("(no field)");
		if (size == 0 || !exactMatch || size == parentDt.getLength()) {
			res.add("(no field)");
		}
		for (DataTypeComponent component : components) {
			String nm = component.getFieldName();
			if (nm == null || nm.length() == 0) {
				nm = component.getDefaultFieldName();
			}
			allFields.add(nm);
			int compStart = component.getOffset();
			int compEnd = compStart + component.getLength();

			if (size == 0 || (exactMatch && startOff == compStart && endOff == compEnd) ||
				(!exactMatch && startOff >= compStart && endOff <= compEnd)) {
				res.add(nm);
			}
		}
		String[] resArray = new String[res.size()];
		res.toArray(resArray);
		return resArray;
	}

	/**
	 * Let the user choose the particular field to force on the selected Varnode. The names
	 * of the fields in the associated union are presented, possibly along with the special
	 * string "no field". The choices are filtered so that they match the size of the Varnode
	 * being forced.  Its possible that all names are filtered out except the current field
	 * assigned to the Varnode, in which case a confirmation dialog is brought up instead.
	 * @param defaultFieldName is the default name to use when presenting options to the user
	 * @return the index of the selected field or -1 if "no field" was selected
	 */
	private boolean selectFieldNumber(String defaultFieldName) {
		ArrayList<String> allFields = new ArrayList<>();
		String[] choices = buildFieldOptions(allFields);
		if (choices.length < 2) {	// If only one field fits the Varnode
			OkDialog.show("No Field Choices", "Only one field fits the selected variable");
			return false;
		}
		int currentChoice = allFields.indexOf(defaultFieldName);
		if (currentChoice < 0) {
			defaultFieldName = null;
		}
		String userChoice = OptionDialog.showInputChoiceDialog(null,
			"Select Field for " + unionDt.getName(), "Field for " + unionDt.getName() + ": ",
			choices, defaultFieldName, OptionDialog.PLAIN_MESSAGE);
		if (userChoice == null) {
			return false;		// User cancelled when making the choice
		}
		fieldNumber = allFields.indexOf(userChoice);
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
