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
package ghidra.app.plugin.core.register;

import java.awt.event.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.context.*;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.FieldMouseHandlerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.viewer.field.FieldMouseHandler;
import ghidra.framework.cmd.Command;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Shows the registers available in a program along with any values that are set.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Manage register values",
	description = "This plugin provides actions and a component for editing register values across address ranges in a program"
)
//@formatter:on
public class RegisterPlugin extends ProgramPlugin {

	private DockingAction setRegisterAction;
	private RegisterManagerProvider registerMgrProvider;
	private Register[] registers = new Register[0];

	private DockingAction deleteRegisterRangeAction;
	private DockingAction deleteRegisterAtFunctionAction;
	private DockingAction clearRegisterAction;

	private FieldMouseHandlerService fieldMouseHandlerService;
	private RegisterTransitionFieldMouseHandler fieldMouseHandler;

	public RegisterPlugin(PluginTool tool) {
		super(tool, true, true);
	}

	@Override
	protected void init() {
		registerMgrProvider = new RegisterManagerProvider(tool, getName());
		tool.addComponentProvider(registerMgrProvider, false);
		createActions();
		fieldMouseHandlerService = tool.getService(FieldMouseHandlerService.class);
		fieldMouseHandler = new RegisterTransitionFieldMouseHandler();
		if (fieldMouseHandlerService != null) {
			fieldMouseHandlerService.addFieldMouseHandler(fieldMouseHandler);
		}
	}

	@Override
	protected void dispose() {
		registerMgrProvider.dispose();
		super.dispose();
	}

	private void createActions() {

		setRegisterAction = new DockingAction("Set Register Values", getName()) {
			@Override
			public void actionPerformed(ActionContext actionContext) {
				ProgramLocationActionContext programActionContext =
					getProgramActionContext(actionContext);
				setRegisterValues(programActionContext);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return (contextObject instanceof ListingActionContext) ||
					(contextObject instanceof RegisterManagerProvider);
			}
		};
		setRegisterAction.setPopupMenuData(
			new MenuData(new String[] { "Set Register Values..." }, null, "Registers"));
		setRegisterAction.setKeyBindingData(
			new KeyBindingData(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK));

		setRegisterAction.setDescription("Set register values in a program.");
		setRegisterAction.setHelpLocation(new HelpLocation("RegisterPlugin", "SetRegisterValues"));
		setRegisterAction.setEnabled(true);

		tool.addAction(setRegisterAction);

		clearRegisterAction = new DockingAction("Clear Register Values", getName()) {
			@Override
			public void actionPerformed(ActionContext actionContext) {
				ProgramLocationActionContext programActionContext =
					getProgramActionContext(actionContext);
				clearRegisterValues(programActionContext);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return (contextObject instanceof ListingActionContext) ||
					(contextObject instanceof RegisterManagerProvider);
			}
		};
		clearRegisterAction.setPopupMenuData(
			new MenuData(new String[] { "Clear Register Values..." }, null, "Registers"));

		clearRegisterAction.setDescription("Clear register values in a program.");
		clearRegisterAction.setHelpLocation(
			new HelpLocation("RegisterPlugin", "ClearRegisterValues"));
		clearRegisterAction.setEnabled(true);

		tool.addAction(clearRegisterAction);

		deleteRegisterRangeAction =
			new ListingContextAction("Delete Register Value Range", getName()) {
				@Override
				public void actionPerformed(ListingActionContext context) {
					deleteRegisterValueRange(context);
				}

				@Override
				public boolean isEnabledForContext(ListingActionContext context) {
					if (context.getLocation() instanceof RegisterTransitionFieldLocation) {
						RegisterTransitionFieldLocation loc =
							(RegisterTransitionFieldLocation) context.getLocation();
						if (loc.getRegister() != null) {
							Address addr = loc.getAddress();
							Register reg = loc.getRegister();
							RegisterValue regVal =
								context.getProgram().getProgramContext().getNonDefaultValue(reg,
									addr);
							return regVal != null && regVal.hasValue();
						}
					}
					return false;
				}
			};
		deleteRegisterRangeAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));

		deleteRegisterRangeAction.setDescription("Delete register value at Function.");
		deleteRegisterRangeAction.setHelpLocation(
			new HelpLocation("RegisterPlugin", "DeleteRegisterValueRange"));
		deleteRegisterRangeAction.setEnabled(true);

		tool.addAction(deleteRegisterRangeAction);

		deleteRegisterAtFunctionAction =
			new ListingContextAction("Delete Register Value Range", getName()) {
				@Override
				public void actionPerformed(ListingActionContext context) {
					deleteRegisterValueAtFunction(context);
				}

				@Override
				public boolean isEnabledForContext(ListingActionContext context) {
					if (context.getLocation() instanceof RegisterFieldLocation) {
						RegisterFieldLocation loc = (RegisterFieldLocation) context.getLocation();
						if (loc.getRegister() != null) {
							Address addr = loc.getAddress();
							Register reg = loc.getRegister();
							RegisterValue regVal =
								context.getProgram().getProgramContext().getNonDefaultValue(reg,
									addr);
							return regVal != null && regVal.hasValue();
						}
					}
					return false;
				}
			};
		deleteRegisterAtFunctionAction.setPopupMenuData(
			new MenuData(new String[] { "Delete Register Value Range..." }, null, "Registers"));
		deleteRegisterAtFunctionAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));

		deleteRegisterAtFunctionAction.setDescription("Delete register value range.");
		deleteRegisterAtFunctionAction.setHelpLocation(
			new HelpLocation("RegisterPlugin", "DeleteRegisterValueRange"));
		deleteRegisterAtFunctionAction.setEnabled(true);

		tool.addAction(deleteRegisterAtFunctionAction);

		registerMgrProvider.createActions();
	}

	private ProgramLocationActionContext getProgramActionContext(ActionContext actionContext) {
		if (actionContext.getContextObject() instanceof ListingActionContext) {
			return (ListingActionContext) actionContext.getContextObject();
		}
		return new ProgramLocationActionContext(null, currentProgram, currentLocation,
			currentSelection, null);
	}

	protected void deleteRegisterValueRange(ListingActionContext context) {
		RegisterTransitionFieldLocation location =
			(RegisterTransitionFieldLocation) context.getLocation();
		Register register = location.getRegister();
		Address addr = location.getAddress();
		ProgramContext programContext = context.getProgram().getProgramContext();
		AddressRangeIterator it = programContext.getRegisterValueAddressRanges(register);
		while (it.hasNext()) {
			AddressRange range = it.next();
			if (range.contains(addr)) {
				Command cmd = new SetRegisterCmd(register, range.getMinAddress(),
					range.getMaxAddress(), null);
				if (!tool.execute(cmd, context.getProgram())) {
					Msg.showError(this, tool.getToolFrame(), "Register Context Error",
						cmd.getStatusMsg());
				}
				return;
			}
		}
	}

	protected void deleteRegisterValueAtFunction(ListingActionContext context) {
		RegisterFieldLocation location = (RegisterFieldLocation) context.getLocation();
		Register register = location.getRegister();
		Address addr = location.getAddress();
		Command cmd = new SetRegisterCmd(register, addr, addr, null);
		if (!tool.execute(cmd, context.getProgram())) {
			Msg.showError(this, tool.getToolFrame(), "Register Context Error", cmd.getStatusMsg());
		}
	}

	protected Register getRegister(ProgramLocationActionContext context) {
		Program program = context.getProgram();
		ProgramLocation location = context.getLocation();
		if (location instanceof OperandFieldLocation) {
			OperandFieldLocation opLoc = (OperandFieldLocation) location;
			CodeUnit cu = program.getListing().getCodeUnitAt(opLoc.getAddress());
			if (cu instanceof Instruction) {
				Instruction inst = (Instruction) cu;
				Object[] opObjs = inst.getOpObjects(opLoc.getOperandIndex());
				for (Object object : opObjs) {
					if (object instanceof Register) {
						return (Register) object;
					}
				}
			}
		}
		return null;
	}

	protected void setRegisterValues(ProgramLocationActionContext context) {
		Register register = getRegister(context);
		AddressSetView addrSet = getAddressSet(context);
		if (register == null) {
			register = registerMgrProvider.getSelectedRegister();
		}
		setRegisterValues(context, register, addrSet, true);
	}

	void clearRegisterValues(ProgramLocationActionContext context) {
		Register register = getRegister(context);
		AddressSetView addrSet = getAddressSet(context);
		if (register == null) {
			register = registerMgrProvider.getSelectedRegister();
		}
		SetRegisterValueDialog dialog =
			new SetRegisterValueDialog(context.getProgram(), registers, register, addrSet, false);

		tool.showDialog(dialog);

		Register selectedRegister = dialog.getSelectRegister();
		if (selectedRegister != null) {
			applyRegisterValues(context.getProgram(), selectedRegister, null, addrSet);
		}
	}

	void setRegisterValues(ProgramLocationActionContext context, Register register,
			AddressSetView addrSet, boolean selectRegister) {

		SetRegisterValueDialog dialog =
			new SetRegisterValueDialog(context.getProgram(), registers, register, addrSet, true);

		tool.showDialog(dialog);

		BigInteger value = dialog.getRegisterValue();
		Register selectedRegister = dialog.getSelectRegister();
		if (value != null && selectedRegister != null) {
			applyRegisterValues(context.getProgram(), selectedRegister, value, addrSet);
			if (selectRegister) {
				registerMgrProvider.selectRegister(selectedRegister);
			}
		}
	}

	private AddressSetView getAddressSet(ProgramLocationActionContext context) {
		if (context.hasSelection()) {
			return context.getSelection();
		}
		if (context.getAddress() != null) {
			Address address = context.getAddress();
			return new AddressSet(address, address);
		}
		return new AddressSet();
	}

//==================================================================================================
//  ProgramPlugin and DomainObjectListener methods  
//==================================================================================================

	@Override
	protected void programActivated(Program program) {
		registerMgrProvider.setProgram(program);
		ArrayList<Register> list = new ArrayList<>();
		for (Register reg : program.getProgramContext().getRegisters()) {
			if (!reg.isHidden()) {
				list.add(reg);
			}
		}
		Collections.sort(list);
		registers = new Register[list.size()];
		registers = list.toArray(registers);
	}

	@Override
	protected void programDeactivated(Program program) {
		registerMgrProvider.setProgram(null);
		registers = new Register[0];
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		if (loc instanceof RegisterTransitionFieldLocation) {
			RegisterTransitionFieldLocation regLoc = (RegisterTransitionFieldLocation) loc;
			Register reg = regLoc.getRegister();
			if (reg != null) {
				registerMgrProvider.setLocation(reg, regLoc.getAddress());
			}
		}
		else if (loc instanceof RegisterFieldLocation) {
			RegisterFieldLocation regLoc = (RegisterFieldLocation) loc;
			Register reg = regLoc.getRegister();
			if (reg != null) {
				registerMgrProvider.setLocation(reg, regLoc.getAddress());
			}
		}
		if (loc instanceof CodeUnitLocation) {
			registerMgrProvider.setLocation(null, loc.getAddress());
		}
	}

	private void applyRegisterValues(Program program, Register register, BigInteger value,
			AddressSetView addressSet) {
		if (program == null || addressSet.isEmpty()) {
			return;
		}

		CompoundCmd cmd = new CompoundCmd("Set Register Values");
		for (AddressRange range : addressSet) {
			SetRegisterCmd regCmd =
				new SetRegisterCmd(register, range.getMinAddress(), range.getMaxAddress(), value);
			cmd.add(regCmd);
		}
		if (!tool.execute(cmd, program)) {
			Msg.showError(this, tool.getToolFrame(), "Register Context Error", cmd.getStatusMsg());
		}
	}

	class RegisterTransitionFieldMouseHandler implements FieldMouseHandler {
		@Override
		public boolean fieldElementClicked(Object clickedObject, Navigatable sourceNavigatable,
				ProgramLocation location, MouseEvent mouseEvent, ServiceProvider serviceProvider) {
			if (mouseEvent.getClickCount() != 2) {
				return false;
			}
			Register reg = null;
			if (location instanceof RegisterTransitionFieldLocation) {
				RegisterTransitionFieldLocation loc = (RegisterTransitionFieldLocation) location;
				reg = loc.getRegister();
			}
			else if (location instanceof RegisterFieldLocation) {
				RegisterFieldLocation loc = (RegisterFieldLocation) location;
				reg = loc.getRegister();
			}
			ProgramManager programManager = serviceProvider.getService(ProgramManager.class);
			if (programManager == null) {
				return false;
			}
			Program activeProgram = programManager.getCurrentProgram();

			if (reg != null && activeProgram == sourceNavigatable.getProgram()) {
				tool.showComponentProvider(registerMgrProvider, true);
				registerMgrProvider.setLocation(reg, location.getAddress());
			}
			return true;
		}

		@Override
		public Class<?>[] getSupportedProgramLocations() {
			return new Class[] { RegisterTransitionFieldLocation.class,
				RegisterFieldLocation.class };
		}

	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		super.serviceAdded(interfaceClass, service);
		if (interfaceClass == FieldMouseHandlerService.class && fieldMouseHandlerService == null) {
			fieldMouseHandlerService = (FieldMouseHandlerService) service;
			fieldMouseHandlerService.addFieldMouseHandler(fieldMouseHandler);
		}
	}

	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		if (interfaceClass == FieldMouseHandlerService.class && fieldMouseHandlerService != null &&
			fieldMouseHandlerService == service && fieldMouseHandler != null) {
			// Should FieldMouseHandlerService have a removeFieldMouseHandler() method?
			fieldMouseHandlerService = null;
		}
		super.serviceRemoved(interfaceClass, service);
	}
}
