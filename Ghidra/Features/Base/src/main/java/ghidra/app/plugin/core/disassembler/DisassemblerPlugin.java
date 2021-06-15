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
package ghidra.app.plugin.core.disassembler;

import docking.action.DockingAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.disassemble.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * <CODE>DisassemblerPlugin</CODE> provides functionality for dynamic disassembly,
 * static disassembly.<BR>
 * In dynamic disassembly disassembling begins from the
 * selected addresses or if there is no selection then at the address of the
 * current cursor location and attempts to continue disassembling
 * through fallthroughs and along all flows from a disassembled instruction.
 * For instance, if a jump instruction is disassembled then the address being
 * jumped to will be disassembled. The dynamic disassembly will also follow
 * data pointers to addresses containing undefined data, which is then
 * disassembled.<BR>
 * In static disassembly a range or set of ranges
 * is given and disassembly is attempted on each range. Any defined code in the
 * ranges before the static disassembly are first removed.<BR>
 * <P>
 * <CODE>DisassemblerPlugin</CODE> provides access to its functions as a service
 * that another plugin may use and through the popup menu to the user.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Disassembler",
	description = "This plugin provides functionality for dynamic disassembly, "
			+ "static disassembly. In dynamic disassembly, disassembling begins from the "
			+ "selected addresses or if there is no selection then at the address of the "
			+ "current cursor location and attempts to continue disassembling "
			+ "through fallthroughs and along all flows from a disassembled instruction. "
			+ "For instance, if a jump instruction is disassembled then the address being "
			+ "jumped to will be disassembled. The dynamic disassembly will also follow "
			+ "data pointers to addresses containing undefined data, which is then "
			+ "disassembled.  In static disassembly a range or set of ranges "
			+ "is given and disassembly is attempted on each range. Any defined code in the "
			+ "ranges before the static disassembly are first removed.",
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class DisassemblerPlugin extends Plugin {

	// action info
	final static String GROUP_NAME = "Disassembly";

	// actions
	private DockingAction disassembleRestrictedAction;
	private DockingAction disassembleAction;
	private DockingAction disassembleStaticAction;
	private DockingAction contextAction;
	private DockingAction armDisassembleAction;
	private DockingAction armThumbDisassembleAction;
	private DockingAction hcs12DisassembleAction;
	private DockingAction xgateDisassembleAction;
	private DockingAction mipsDisassembleAction;
	private DockingAction mips16DisassembleAction;
	private DockingAction ppcDisassembleAction;
	private DockingAction ppcVleDisassembleAction;
	private DockingAction setFlowOverrideAction;

	/** Dialog for obtaining the processor state to be used for disassembling. */
//	private ProcessorStateDialog processorStateDialog;

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	// static class methods                                             //
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	/**
	 * Get the description of this plugin.
	 */
	public static String getDescription() {
		return "Provides disassembler services for all supplied machine language modules.";
	}

	/**
	 * Get the descriptive name.
	 */
	public static String getDescriptiveName() {
		return "Disassembler";
	}

	/**
	 * Get the category.
	 */
	public static String getCategory() {
		return "Disassemblers";
	}

	//////////////////////////////////////////////////////////////////////
	//                                                                  //
	// Constructor                                                      //
	//                                                                  //
	//////////////////////////////////////////////////////////////////////

	/**
	 * Creates a new instance of the plugin giving it the tool that
	 * it will work in.
	 */
	public DisassemblerPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent ev = (ProgramActivatedPluginEvent) event;
			programActivated(ev.getActiveProgram());
		}
	}

	protected void programActivated(Program program) {
		if (program == null) {
			return;
		}
		Options options = program.getOptions(Program.DISASSEMBLER_PROPERTIES);
		options.registerOption(Disassembler.MARK_BAD_INSTRUCTION_PROPERTY, true,
			null, "Place ERROR Bookmark at locations where disassembly could not be perfomed.");
		options.registerOption(
			Disassembler.MARK_UNIMPL_PCODE_PROPERTY,
			true,
			null,
			"Place WARNING Bookmark at locations where a disassembled instruction has unimplemented pcode.");
		options.registerOption(Disassembler.RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY,
			false, null, "Restrict disassembly to executable memory blocks.");
	}

	//////////////////////////////////////////////////////////////////////
	// private methods                                                  //
	//////////////////////////////////////////////////////////////////////

	/**
	 * Creates actions for the plugin.
	 */
	private void createActions() {
		disassembleAction = new DisassembleAction(this, GROUP_NAME);
		disassembleRestrictedAction = new RestrictedDisassembleAction(this, GROUP_NAME);
		disassembleStaticAction = new StaticDisassembleAction(this, GROUP_NAME);
		contextAction = new ContextAction(this, GROUP_NAME);
		armDisassembleAction = new ArmDisassembleAction(this, GROUP_NAME, false);
		armThumbDisassembleAction = new ArmDisassembleAction(this, GROUP_NAME, true);
		hcs12DisassembleAction = new Hcs12DisassembleAction(this, GROUP_NAME, false);
		xgateDisassembleAction = new Hcs12DisassembleAction(this, GROUP_NAME, true);
		mipsDisassembleAction = new MipsDisassembleAction(this, GROUP_NAME, false);
		mips16DisassembleAction = new MipsDisassembleAction(this, GROUP_NAME, true);
		ppcDisassembleAction = new PowerPCDisassembleAction(this, GROUP_NAME, false);
		ppcVleDisassembleAction= new PowerPCDisassembleAction(this, GROUP_NAME, true);
		setFlowOverrideAction = new SetFlowOverrideAction(this, GROUP_NAME);

		tool.addAction(disassembleAction);
		tool.addAction(disassembleRestrictedAction);
		tool.addAction(disassembleStaticAction);
		tool.addAction(armDisassembleAction);
		tool.addAction(armThumbDisassembleAction);
		tool.addAction(hcs12DisassembleAction);
		tool.addAction(xgateDisassembleAction);
		tool.addAction(mipsDisassembleAction);
		tool.addAction(mips16DisassembleAction);
		tool.addAction(ppcDisassembleAction);
		tool.addAction(ppcVleDisassembleAction);
		tool.addAction(contextAction);
		tool.addAction(setFlowOverrideAction);
	}

	void disassembleRestrictedCallback(ListingActionContext context) {
		ProgramSelection currentSelection = context.getSelection();
		ProgramLocation currentLocation = context.getLocation();
		Program currentProgram = context.getProgram();
		DisassembleCommand cmd = null;

		if ((currentSelection != null) && (!currentSelection.isEmpty())) {
			cmd = new DisassembleCommand(currentSelection, currentSelection, true);
		}
		else {
			Address addr = currentLocation.getAddress();
			cmd = new DisassembleCommand(addr, new AddressSet(addr, addr), true);
		}
		tool.executeBackgroundCommand(cmd, currentProgram);
	}

	void disassembleStaticCallback(ListingActionContext context) {
		ProgramSelection currentSelection = context.getSelection();
		ProgramLocation currentLocation = context.getLocation();
		Program currentProgram = context.getProgram();

		DisassembleCommand cmd = null;

		if ((currentSelection != null) && (!currentSelection.isEmpty())) {
			cmd = new DisassembleCommand(currentSelection, currentSelection, false);
		}
		else {
			Address addr = currentLocation.getAddress();
			cmd = new DisassembleCommand(addr, new AddressSet(addr, addr), false);
		}
		tool.executeBackgroundCommand(cmd, currentProgram);
	}

	void disassembleCallback(ListingActionContext context) {
		ProgramSelection currentSelection = context.getSelection();
		ProgramLocation currentLocation = context.getLocation();
		Program currentProgram = context.getProgram();
		DisassembleCommand cmd = null;

		boolean isDynamicListing =
			(context instanceof CodeViewerActionContext && ((CodeViewerActionContext) context).isDyanmicListing());

		if ((currentSelection != null) && (!currentSelection.isEmpty())) {
			cmd = new DisassembleCommand(currentSelection, null, true);
		}
		else {
			Address addr = currentLocation.getAddress();
			try {
				currentProgram.getMemory().getByte(addr);
				AddressSetView restrictedSet = null;
				if (isDynamicListing) {
					// TODO: should we have option to control restricted range?
					Address min, max;
					try {
						min = addr.subtractNoWrap(1000);
					}
					catch (AddressOverflowException e) {
						min = addr.getAddressSpace().getMinAddress();
					}
					try {
						max = addr.addNoWrap(1000);
					}
					catch (AddressOverflowException e) {
						max = addr.getAddressSpace().getMaxAddress();
					}
					restrictedSet = new AddressSet(min, max);
				}
				cmd = new DisassembleCommand(addr, restrictedSet, true);
			}
			catch (MemoryAccessException e) {
				tool.setStatusInfo("Can't disassemble unitialized memory!", true);
			}
		}
		if (cmd != null) {
			cmd.enableCodeAnalysis(!isDynamicListing); // do not analyze debugger listing
			tool.executeBackgroundCommand(cmd, currentProgram);
		}
	}

	boolean checkDisassemblyEnabled(ListingActionContext context, Address address, boolean followPtr) {
		ProgramSelection currentSelection = context.getSelection();
		Program currentProgram = context.getProgram();
		if ((currentSelection != null) && (!currentSelection.isEmpty())) {
			return true;
		}

		Listing listing = currentProgram.getListing();

		if (listing.getInstructionContaining(address) != null) {
			return false;
		}
		Data data = listing.getDefinedDataContaining(address);
		if (data != null) {
			if (followPtr && data.isPointer()) {
				Address ptrAddr = data.getAddress(0);
				if (ptrAddr != null) {
					return checkDisassemblyEnabled(context, ptrAddr, false);
				}
			}
			return false;
		}
		return currentProgram.getMemory().contains(address);
	}

	public void setDefaultContext(ListingActionContext context) {
		Program contextProgram = context.getProgram();
		Register baseContextReg = contextProgram.getLanguage().getContextBaseRegister();
		if (baseContextReg != null && baseContextReg.hasChildren()) {
			tool.showDialog(new ProcessorStateDialog(contextProgram.getProgramContext()),
				context.getComponentProvider());
		}
	}

	public boolean hasContextRegisters(Program currentProgram) {
		Register baseContextReg = currentProgram.getLanguage().getContextBaseRegister();
		return baseContextReg != null && baseContextReg.hasChildren();
	}

	public void disassembleArmCallback(ListingActionContext context, boolean thumbMode) {
		ProgramSelection currentSelection = context.getSelection();
		ProgramLocation currentLocation = context.getLocation();
		Program currentProgram = context.getProgram();
		ArmDisassembleCommand cmd = null;

		if ((currentSelection != null) && (!currentSelection.isEmpty())) {
			cmd = new ArmDisassembleCommand(currentSelection, null, thumbMode);
		}
		else {
			Address addr = currentLocation.getAddress();
			try {
				currentProgram.getMemory().getByte(addr);
				cmd = new ArmDisassembleCommand(addr, null, thumbMode);
			}
			catch (MemoryAccessException e) {
				tool.setStatusInfo("Can't disassemble unitialized memory!", true);
			}
		}
		if (cmd != null) {
			tool.executeBackgroundCommand(cmd, currentProgram);
		}
	}
	
	public void disassembleHcs12Callback(ListingActionContext context, boolean xgMode) {
		ProgramSelection currentSelection = context.getSelection();
		ProgramLocation currentLocation = context.getLocation();
		Program currentProgram = context.getProgram();
		Hcs12DisassembleCommand cmd = null;

		if ((currentSelection != null) && (!currentSelection.isEmpty())) {
			cmd = new Hcs12DisassembleCommand(currentSelection, null, xgMode);
		}
		else {
			Address addr = currentLocation.getAddress();
			try {
				currentProgram.getMemory().getByte(addr);
				cmd = new Hcs12DisassembleCommand(addr, null, xgMode);
			}
			catch (MemoryAccessException e) {
				tool.setStatusInfo("Can't disassemble unitialized memory!", true);
			}
		}
		if (cmd != null) {
			tool.executeBackgroundCommand(cmd, currentProgram);
		}
	}
	
	public void disassembleMipsCallback(ListingActionContext context, boolean mips16) {
		ProgramSelection currentSelection = context.getSelection();
		ProgramLocation currentLocation = context.getLocation();
		Program currentProgram = context.getProgram();
		MipsDisassembleCommand cmd = null;

		if ((currentSelection != null) && (!currentSelection.isEmpty())) {
			cmd = new MipsDisassembleCommand(currentSelection, null, mips16);
		}
		else {
			Address addr = currentLocation.getAddress();
			try {
				currentProgram.getMemory().getByte(addr);
				cmd = new MipsDisassembleCommand(addr, null, mips16);
			}
			catch (MemoryAccessException e) {
				tool.setStatusInfo("Can't disassemble unitialized memory!", true);
			}
		}
		if (cmd != null) {
			tool.executeBackgroundCommand(cmd, currentProgram);
		}
	}

	public void disassemblePPCCallback(ListingActionContext context, boolean vle) {
		ProgramSelection currentSelection = context.getSelection();
		ProgramLocation currentLocation = context.getLocation();
		Program currentProgram = context.getProgram();
		PowerPCDisassembleCommand cmd = null;
		
		if ((currentSelection != null) && (!currentSelection.isEmpty())) {
			cmd = new PowerPCDisassembleCommand(currentSelection, null, vle);
		}
		else {
			Address addr = currentLocation.getAddress();
			try {
				currentProgram.getMemory().getByte(addr);
				cmd = new PowerPCDisassembleCommand(addr, null, vle);
			}
			catch (MemoryAccessException e) {
				tool.setStatusInfo("Can't disassemble unitialized memory!", true);
			}
		}
		if (cmd != null) {
			tool.executeBackgroundCommand(cmd, currentProgram);
		}
	}

}
