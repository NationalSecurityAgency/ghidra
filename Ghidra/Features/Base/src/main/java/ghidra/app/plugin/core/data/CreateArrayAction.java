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
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.NumberInputDialog;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.cmd.data.CreateArrayInStructureCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.*;

class CreateArrayAction extends DockingAction {

	private static final KeyStroke DEFAULT_KEY_STROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_OPEN_BRACKET, 0);
	private static final String[] CREATE_ARRAY_POPUP_MENU =
		new String[] { "Data", "Create Array..." };

	private DataPlugin plugin;

	public CreateArrayAction(DataPlugin plugin) {
		super("Define Array", plugin.getName(), KeyBindingType.SHARED);
		this.plugin = plugin;

		setPopupMenuData(new MenuData(CREATE_ARRAY_POPUP_MENU, "BasicData"));
		setEnabled(true);

		initKeyStroke(DEFAULT_KEY_STROKE);
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
		Program program = programActionContext.getProgram();
		ProgramLocation loc = programActionContext.getLocation();
		ProgramSelection sel = programActionContext.getSelection();

		if (sel != null && !sel.isEmpty()) {
			InteriorSelection interiorSel = sel.getInteriorSelection();
			if (interiorSel != null) {
				createArrayInStructure(program, interiorSel);
			}
			else {
				createArrayFromSelection(program, sel);
			}
		}
		else {
			int[] compPath = loc.getComponentPath();
			if (compPath != null && compPath.length > 0) {
				createArrayInStructure(program, loc.getAddress(), compPath);
			}
			else {
				createArrayAtAddress(program, loc.getAddress());
			}
		}
	}

	private void createArrayInStructure(Program program, Address addr, int[] compPath) {
		PluginTool tool = plugin.getTool();
		Data data = program.getListing().getDataContaining(addr);
		Data comp = null;
		if (data != null) {
			comp = data.getComponent(compPath);
		}

		if (comp == null) {
			tool.setStatusInfo("Create Array Failed! No data at " + addr);
			return;
		}
		DataType dt = comp.getDataType();
		DataType parentDataType = comp.getParent().getBaseDataType();

		if (!(parentDataType instanceof Structure)) {
			tool.setStatusInfo("Cannot create array here");
			return;
		}
		Structure struct = (Structure) parentDataType;

		int maxElements = getMaxElements(struct, comp.getComponentIndex(), dt);
		int maxNoConflictElements = getMaxNoConflictElements(struct, comp.getComponentIndex(), dt);
		int numElements = getNumElements(dt, maxNoConflictElements, maxElements);

		Command cmd = new CreateArrayInStructureCmd(addr, numElements, dt, compPath);
		if (!tool.execute(cmd, program)) {
			tool.setStatusInfo(cmd.getStatusMsg());
		}
	}

	private void createArrayInStructure(Program program, InteriorSelection sel) {
		PluginTool tool = plugin.getTool();
		ProgramLocation from = sel.getFrom();

		Data data = program.getListing().getDataContaining(from.getAddress());
		Data comp = null;
		if (data != null) {
			comp = data.getComponent(from.getComponentPath());
		}

		if (comp == null) {
			tool.setStatusInfo("Create Array Failed! No data at " + from.getAddress());
			return;
		}
		DataType dt = comp.getDataType();
		DataType parentDataType = comp.getParent().getBaseDataType();

		if (!(parentDataType instanceof Structure)) {
			tool.setStatusInfo("Cannot create array here");
			return;
		}

		int length = sel.getByteLength();
		int numElements = length / dt.getLength();

		Command cmd = new CreateArrayInStructureCmd(from.getAddress(), numElements, dt,
			from.getComponentPath());
		if (!tool.execute(cmd, program)) {
			tool.setStatusInfo(cmd.getStatusMsg());
		}
	}

	private int getMaxNoConflictElements(Structure struct, int index, DataType dt) {
		int n = struct.getNumComponents();
		int length = 0;
		while (index < n) {
			DataTypeComponent dtc = struct.getComponent(index++);
			DataType dataType = dtc.getDataType();
			if ((dataType != DataType.DEFAULT) && (dataType != dt)) {
				break;
			}
			length += dtc.getLength();
		}
		return length / dt.getLength();
	}

	private int getMaxElements(Structure struct, int index, DataType dt) {
		int n = struct.getNumComponents();
		int length = 0;
		while (index < n) {
			DataTypeComponent dtc = struct.getComponent(index++);
			length += dtc.getLength();
		}
		return length / dt.getLength();
	}

	private void createArrayAtAddress(Program program, Address addr) {
		PluginTool tool = plugin.getTool();
		Data data = program.getListing().getDataAt(addr);
		if (data == null) {
			tool.setStatusInfo("Create Array Failed! No data at " + addr);
			return;
		}

		DataType dt = data.getDataType();
		int length = data.getLength();
		int maxNoConflictElements = getMaxElementsThatFit(program, addr, length);
		int maxElements = getMaxElementsIgnoreExisting(program, addr, length);
		int numElements = getNumElements(dt, maxNoConflictElements, maxElements);

		// this signals that the user cancelled the operation
		if (numElements == Integer.MIN_VALUE) {
			return;
		}

		CreateArrayCmd cmd = new CreateArrayCmd(addr, numElements, dt, length);
		if (!tool.execute(cmd, program)) {
			tool.setStatusInfo(cmd.getStatusMsg());
		}
	}

	private void createArrayFromSelection(Program program, ProgramSelection sel) {
		PluginTool tool = plugin.getTool();

		AddressRange range = sel.getFirstRange();
		Address addr = sel.getMinAddress();
		Data data = program.getListing().getDataAt(addr);
		if (data == null) {
			tool.setStatusInfo("Create Array Failed! No data at " + addr);
			return;
		}
		DataType dt = data.getDataType();
		int dtLength = data.getLength();
		int length = (int) range.getLength();
		int numElements = length / dtLength;
		CreateArrayCmd cmd = new CreateArrayCmd(addr, numElements, dt, dtLength);
		if (!tool.execute(cmd, program)) {
			tool.setStatusInfo(cmd.getStatusMsg());
		}
	}

	/**
	 * Get the number of elements to create from the user.
	 */
	private int getNumElements(final DataType dt, final int maxNoConflictElements,
			final int maxElements) {
		NumberInputDialog numberInputDialog = new NumberInputDialog("Create " + dt.getName() + "[]",
			"Enter number of array elements (1 - " + maxElements + ") :", maxNoConflictElements, 1,
			maxElements, false);
		if (maxNoConflictElements < maxElements) {
			numberInputDialog.setDefaultMessage(
				"Entering more than " + maxNoConflictElements + " will overwrite existing data");
		}
		if (!numberInputDialog.show()) {
			return Integer.MIN_VALUE; // cancelled
		}
		int value = numberInputDialog.getValue();
		if (value > maxNoConflictElements) {
			int result = OptionDialog.showYesNoDialog(null, "Overwrite Existing Data?",
				"Existing data will be overridden if you create this array.\n" +
					"Are you sure you want to continue?");
			if (result != OptionDialog.YES_OPTION) {
				return Integer.MIN_VALUE;  	// Cancel create array
			}
		}
		return value;
	}

	/**
	 * Get the maximum number of elements that will fit.  This means the undefined
	 * bytes available up to the next instruction or defined data.
	 *
	 * NOTE: right now this does not include holes in memory, or looking for the
	 * end of memory.  The protoBuf would need to be changed to find the end of the
	 * current memory block and restrict the length to that.
	 *
	 * @return the maximum number of elements for an array of the given data type
	 */
	private int getMaxElementsThatFit(Program program, Address addr, int elementSize) {

		// can't go past the end of a block to start with
		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block == null) {
			return 0;
		}

		Address maxAddr = block.getEnd();

		// get the next non undefined element in memory
		Instruction instr = program.getListing().getInstructionAfter(addr);
		if (instr != null) {
			Address instrAddr = instr.getMinAddress();
			if (instrAddr.compareTo(maxAddr) < 0) {
				maxAddr = instrAddr.subtract(1);
			}
		}

		// get the next non undefined data element in memory
		Data data = DataUtilities.getNextNonUndefinedDataAfter(program, addr, maxAddr);
		if (data != null) {
			Address dataAddr = data.getMinAddress();
			if (dataAddr.compareTo(maxAddr) < 0) {
				maxAddr = dataAddr.subtract(1);
			}
		}

		int length = (int) maxAddr.subtract(addr) + 1;
		if (length < 0) {
			return 0;
		}
		return (length / elementSize);
	}

	/**
	 * Get the maximum number of elements that will fit.  This means the undefined
	 * bytes available up to the next instruction or end of defined memory.
	 * 
	 * @return the maximum number of elements for an array of the given data type
	 */
	private int getMaxElementsIgnoreExisting(Program program, Address addr, int elementSize) {

		// can't go past the end of a block to start with
		AddressSetView asv = program.getMemory();
		AddressRange range = asv.getRangeContaining(addr);
		if (range == null) {
			return 0;
		}
		Address maxAddress = range.getMaxAddress();

		Instruction instructionAfter = program.getListing().getInstructionAfter(addr);
		if (instructionAfter != null && maxAddress.compareTo(instructionAfter.getAddress()) > 0) {
			maxAddress = instructionAfter.getAddress().previous();
		}

		int length = (int) maxAddress.subtract(addr) + 1;
		if (length < 0) {
			return 0;
		}
		return (length / elementSize);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		Object contextObject = context.getContextObject();
		if (contextObject instanceof ListingActionContext) {
			return plugin.isCreateDataAllowed(((ListingActionContext) contextObject));
		}
		return false;
	}

}
