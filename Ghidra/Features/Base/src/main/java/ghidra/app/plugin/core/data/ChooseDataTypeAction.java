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

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.SystemUtilities;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

/**
 * An action that allows the user to change or select a data type.
 */
public class ChooseDataTypeAction extends DockingAction {

	private DataPlugin plugin;
	private static final KeyStroke KEY_BINDING = KeyStroke.getKeyStroke(KeyEvent.VK_T, 0);
	private final static String ACTION_NAME = "Choose Data Type";

	public ChooseDataTypeAction(DataPlugin plugin) {
		super(ACTION_NAME, plugin.getName(), KeyBindingType.SHARED);
		this.plugin = plugin;

		initKeyStroke(KEY_BINDING);
	}

	private void initKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return;
		}

		setKeyBindingData(new KeyBindingData(keyStroke));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		ListingActionContext programActionContext =
			(ListingActionContext) context.getContextObject();
		int maxSize = Integer.MAX_VALUE;
		Program program = programActionContext.getProgram();
		ProgramLocation loc = programActionContext.getLocation();
		ProgramSelection sel = programActionContext.getSelection();
		if (sel != null && !sel.isEmpty()) {
			InteriorSelection interiorSel = sel.getInteriorSelection();
			if (interiorSel != null) {
				maxSize = getSizeInsideStructure(program, interiorSel);
			}
			else {
				maxSize = getSizeForSelection(program, sel);
			}
		}
		else {
			int[] compPath = loc.getComponentPath();
			if (compPath != null && compPath.length > 0) {
				maxSize = getSizeInsideStructure(program, loc);
			}
			else {
				maxSize = getSizeForAddress(program, loc);
			}
		}

		// unable to create data types at the current location
		if (maxSize < 0) {
			return;
		}

		Pointer pointer = program.getDataTypeManager().getPointer(null);
		DataType dataType = getDataType(programActionContext, maxSize, pointer.getLength());
		if (dataType != null) {
			plugin.doCreateData(program, loc, sel, dataType, false);
		}
	}

	private int getSizeInsideStructure(Program program, InteriorSelection selection) {
		ProgramLocation location = selection.getFrom();
		Data dataComponent = getParentDataType(program, location);
		if (dataComponent == null) {
			return -1;
		}
		return selection.getByteLength();
	}

	private int getSizeInsideStructure(Program program, ProgramLocation location) {
		Data dataComponent = getParentDataType(program, location);
		if (dataComponent == null) {
			return -1;
		}
		return getMaxSizeInStructure((Structure) dataComponent.getParent().getBaseDataType(),
			dataComponent.getComponentIndex());
	}

	private int getSizeForAddress(Program program, ProgramLocation location) {

		Address address = location.getAddress();
		Data data = program.getListing().getDataAt(address);
		if (data == null) {
			plugin.getTool().setStatusInfo("Create Data Failed! No data at " + address);
			return -1;
		}

		return getMaxSize(program, address);
	}

	private Data getParentDataType(Program program, ProgramLocation location) {

		int[] path = location.getComponentPath();
		Address address = location.getAddress();
		Data data = program.getListing().getDataContaining(address);
		Data dataComponent = null;
		if (data != null) {
			dataComponent = data.getComponent(path);
		}

		if (dataComponent == null) {
			plugin.getTool().setStatusInfo("Create data type failed! No data at " + address);
			return null;
		}

		DataType parentDataType = dataComponent.getParent().getBaseDataType();

		if (!(parentDataType instanceof Structure)) {
			plugin.getTool().setStatusInfo("Cannot set data type here.");
			return null;
		}

		return dataComponent;
	}

	private int getSizeForSelection(Program program, ProgramSelection selection) {

		PluginTool tool = plugin.getTool();

		AddressRange range = selection.getFirstRange();
		Address address = selection.getMinAddress();
		Data data = program.getListing().getDataAt(address);
		if (data == null) {
			tool.setStatusInfo("Cannot set data type! No data at " + address);
			return -1;
		}

		return (int) range.getLength();
	}

	private DataType getDataType(ListingActionContext context, int maxElements,
			int defaultPointerSize) {
		PluginTool tool = plugin.getTool();
		Data data = plugin.getDataUnit(context);
		DataTypeSelectionDialog selectionDialog = new DataTypeSelectionDialog(tool,
			data.getProgram().getDataTypeManager(), maxElements, AllowedDataTypes.ALL);
		DataType currentDataType = data.getBaseDataType();
		selectionDialog.setInitialDataType(currentDataType);
		tool.showDialog(selectionDialog);
		return selectionDialog.getUserChosenDataType();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		Object contextObject = context.getContextObject();
		if (contextObject instanceof ListingActionContext) {
			return plugin.isCreateDataAllowed(((ListingActionContext) contextObject));
		}
		return false;
	}

	private int getMaxSizeInStructure(Structure struct, int index) {
		int n = struct.getNumComponents();
		DataTypeComponent dtc = struct.getComponent(index++);
		int length = dtc.getLength();
		while (index < n) {
			dtc = struct.getComponent(index++);
			DataType dataType = dtc.getDataType();
			if (dataType != DataType.DEFAULT) {
				break;
			}
			length += dtc.getLength();
		}
		return length;
	}

	private int getMaxSize(Program program, Address addr) {

		// can't go past the end of a block to start with
		Address maxAddr = program.getMemory().getBlock(addr).getEnd();

		// get the next non undefined element in memory
		Instruction instr = program.getListing().getInstructionAfter(addr);
		if (instr != null) {
			Address instrAddr = instr.getMinAddress();
			if (instrAddr.compareTo(maxAddr) < 0) {
				maxAddr = instrAddr.subtract(1);
			}
		}

		Data data = DataUtilities.getNextNonUndefinedDataAfter(program, addr, maxAddr);
		if (data != null) {
			Address dataAddr = data.getMinAddress();
			if (dataAddr.compareTo(maxAddr) < 0) {
				maxAddr = dataAddr.subtract(1);
			}
		}

		long length = maxAddr.subtract(addr) + 1;
		SystemUtilities.assertTrue(length > 0,
			"Subtraction an address from the max address in its block should never be negative");
		return length > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) length;
	}
}
