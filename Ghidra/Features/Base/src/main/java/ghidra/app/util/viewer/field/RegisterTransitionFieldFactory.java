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
package ghidra.app.util.viewer.field;

import java.awt.Color;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.RegisterTransitionFieldLocation;

/**
  *  Generates Mnemonic Fields.
  */
public class RegisterTransitionFieldFactory extends FieldFactory {

	private static final String FIELD_NAME = "Register Transition";
	private static final String DISPLAY_HIDDEN_REGISTERS_OPTION_NAME =
		RegisterFieldFactory.DISPLAY_HIDDEN_REGISTERS_OPTION_NAME;
	private Color regColor;
	private boolean showContextRegisters;

	/**
	 * Default constructor.
	 */
	public RegisterTransitionFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hsProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private RegisterTransitionFieldFactory(FieldFormatModel model, HighlightProvider hsProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hsProvider, displayOptions, fieldOptions);
		initOptions(displayOptions, fieldOptions);
	}

	private void initOptions(Options displayOptions, Options fieldOptions) {
		regColor =
			displayOptions.getColor(OptionsGui.REGISTERS.getColorOptionName(), getDefaultColor());

		showContextRegisters = fieldOptions.getBoolean(DISPLAY_HIDDEN_REGISTERS_OPTION_NAME, false);
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.fieldOptionsChanged(options, optionName, oldValue, newValue);

		if (optionName.equals(DISPLAY_HIDDEN_REGISTERS_OPTION_NAME)) {
			showContextRegisters = (Boolean) newValue;
			model.update();
		}
	}

	@Override
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.displayOptionsChanged(options, optionName, oldValue, newValue);

		if (optionName.equals(OptionsGui.REGISTERS.getColorOptionName())) {
			regColor = (Color) newValue;
			model.update();
		}
	}

	/**
	 * Returns the FactoryField for the given object at index index.
	 * @param varWidth the amount of variable width spacing for any fields
	 * before this one.
	 * @param proxy the object whose properties should be displayed.
	 */
	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();

		if (!enabled || !(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;
		Program program = cu.getProgram();
		ProgramContext context = program.getProgramContext();

		Address curAddress = cu.getMinAddress();
		Function function = program.getListing().getFunctionAt(curAddress);
		CodeUnit prevCu = program.getListing().getCodeUnitBefore(curAddress);
		Address prevAddress = prevCu != null ? prevCu.getMinAddress() : null;

		String stackDepthStr = null;
		Integer stackDepthChange = CallDepthChangeInfo.getStackDepthChange(program, curAddress);
		if (stackDepthChange != null) {
			String depthStr = Integer.toString(stackDepthChange);
			String absoluteDepthStr = (depthStr.startsWith("-")) ? depthStr.substring(1) : depthStr;
			stackDepthStr = "StackDepth = StackDepth " + (stackDepthChange > 0 ? "+ " : "- ") +
				absoluteDepthStr;
		}

		List<Register> transitionRegisters =
			getTransitionRegisters(context, function, curAddress, prevAddress);

		if (transitionRegisters.isEmpty() && stackDepthStr == null) {
			return null;
		}
		int numRegisters = transitionRegisters.size();
		int numElements = numRegisters;
		if (stackDepthStr != null) {
			numElements++;
		}
		FieldElement[] fieldElements = new FieldElement[numElements];
		for (int i = 0; i < numRegisters; i++) {
			Register register = transitionRegisters.get(i);
			AttributedString str = new AttributedString("assume " + register.getName() + " = " +
				getValueString(register, context, curAddress), regColor, getMetrics());
			fieldElements[i] = new TextFieldElement(str, i, 0);
		}
		if (stackDepthStr != null) {
			AttributedString str = new AttributedString(stackDepthStr, regColor, getMetrics());
			fieldElements[numRegisters] = new TextFieldElement(str, numRegisters, 0);
		}
		return ListingTextField.createMultilineTextField(this, proxy, fieldElements,
			startX + varWidth, width, Integer.MAX_VALUE, hlProvider);
	}

	private String getValueString(Register register, ProgramContext context, Address curAddress) {
		BigInteger value = context.getValue(register, curAddress, false);
		if (value == null) {
			return "<UNKNOWN>";
		}
		String valueStr = "0x" + value.toString(16);
		RegisterValue defaultValue = context.getDefaultValue(register, curAddress);
		if (defaultValue != null && value.equals(defaultValue.getUnsignedValue())) {
			valueStr += "  (Default)";
		}
		return valueStr;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}

		CodeUnit cu = (CodeUnit) obj;
		Program program = cu.getProgram();
		ProgramContext context = program.getProgramContext();
		Address curAddress = cu.getMinAddress();
		Function function = program.getListing().getFunctionAt(curAddress);
		CodeUnit prevCu = program.getListing().getCodeUnitBefore(curAddress);
		Address prevAddress = prevCu != null ? prevCu.getMinAddress() : null;
		List<Register> transitionRegisters =
			getTransitionRegisters(context, function, curAddress, prevAddress);
		String[] registerNames = getRegisterNames(transitionRegisters);
		return new RegisterTransitionFieldLocation(program, cu.getMinAddress(), registerNames, row,
			col);
	}

	private String[] getRegisterNames(List<Register> transitionRegisters) {
		String[] names = new String[transitionRegisters.size()];
		for (int i = 0; i < names.length; i++) {
			names[i] = transitionRegisters.get(i).getName();
		}
		return names;
	}

	private List<Register> getTransitionRegisters(ProgramContext context, Function function,
			Address currAddr, Address prevAddr) {
		List<Register> transitionRegisters = new ArrayList<>();
		if (function != null) {
			return transitionRegisters; // if at function entry, don't show transitions since
			// the function header already shows register values.
		}
		Register[] registers = context.getRegistersWithValues();
		for (Register register : registers) {
			BigInteger currentValue = context.getValue(register, currAddr, false);
			BigInteger previousValue =
				prevAddr == null ? null : context.getValue(register, prevAddr, false);

			boolean addRegister = !isEqual(currentValue, previousValue);
			if (addRegister && register.isProcessorContext()) {
				// only add context registers if that option is enabled
				addRegister = showContextRegisters;
			}

			if (addRegister) {
				transitionRegisters.add(register);
			}
		}

		if (transitionRegisters.size() > 1) {
			List<Register> dedupedRegisters = new ArrayList<>();
			for (Register register : transitionRegisters) {
				Register parent = register.getParentRegister();
				if (parent == null || !transitionRegisters.contains(parent)) {
					dedupedRegisters.add(register);
				}
			}
			return dedupedRegisters;
		}
		return transitionRegisters;
	}

	private boolean isEqual(BigInteger value1, BigInteger value2) {
		if (value1 == null) {
			return value2 == null;
		}
		return value1.equals(value2);
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {

		if (!(programLoc instanceof RegisterTransitionFieldLocation)) {
			return null;
		}
		RegisterTransitionFieldLocation loc = (RegisterTransitionFieldLocation) programLoc;
		return new FieldLocation(index, fieldNum, loc.getRow(), loc.getCharOffset());
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!CodeUnit.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel fieldFormatModel, HighlightProvider hsProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new RegisterTransitionFieldFactory(fieldFormatModel, hsProvider, displayOptions,
			fieldOptions);
	}

	@Override
	public Color getDefaultColor() {
		return OptionsGui.MNEMONIC.getDefaultColor();
	}
}
