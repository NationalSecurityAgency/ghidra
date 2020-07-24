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
import java.util.*;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
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
import ghidra.program.util.RegisterFieldLocation;

/**
 * Field to show register values at the function entry point.
 */
public class RegisterFieldFactory extends FieldFactory {

	public static final String FIELD_NAME = "Register";
	public static final String REGISTER_GROUP_NAME = "Register Field";
	public static final String DISPLAY_HIDDEN_REGISTERS_OPTION_NAME =
		RegisterFieldFactory.REGISTER_GROUP_NAME + Options.DELIMITER + "Display Hidden Registers";
	public static final String DISPLAY_DEFAULT_REGISTER_VALUES_OPTION_NAME =
		RegisterFieldFactory.REGISTER_GROUP_NAME + Options.DELIMITER +
			"Display Default Register Values";
	private RegComparator regComp;
	private Color regColor;
	private boolean showHiddenRegisters;
	private boolean showDefaultValues;

	public RegisterFieldFactory() {
		super(FIELD_NAME);
	}

	private RegisterFieldFactory(FieldFormatModel model, HighlightProvider highlightProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, highlightProvider, displayOptions, fieldOptions);
		regComp = new RegComparator();
		initDisplayOptions();

		fieldOptions.registerOption(DISPLAY_HIDDEN_REGISTERS_OPTION_NAME, false, null,
			"Shows/hides context registers");
		fieldOptions.registerOption(DISPLAY_DEFAULT_REGISTER_VALUES_OPTION_NAME, false, null,
			"Shows/hides default register values");
		regColor =
			displayOptions.getColor(OptionsGui.REGISTERS.getColorOptionName(), getDefaultColor());

		showHiddenRegisters = fieldOptions.getBoolean(DISPLAY_HIDDEN_REGISTERS_OPTION_NAME, false);
		showDefaultValues =
			fieldOptions.getBoolean(DISPLAY_DEFAULT_REGISTER_VALUES_OPTION_NAME, false);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel,
			HighlightProvider highlightProvider, ToolOptions toolOptions,
			ToolOptions fieldOptions) {
		return new RegisterFieldFactory(formatModel, highlightProvider, toolOptions, fieldOptions);
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {

		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof Function)) {
			return null;
		}
		int x = startX + varWidth;

		Function function = (Function) obj;
		List<Register> setRegisters = getSetRegisters(function);
		if (setRegisters.isEmpty()) {
			return null;
		}
		String[] registerStrings = getRegisterStrings(function, setRegisters);
		return getTextField(registerStrings, proxy, x);
	}

	private String[] getRegisterStrings(Function function, List<Register> setRegisters) {
		Program program = function.getProgram();
		ProgramContext programContext = program.getProgramContext();
		Address address = function.getEntryPoint();
		String[] strings = new String[setRegisters.size()];
		for (int i = 0; i < strings.length; i++) {
			Register register = setRegisters.get(i);
			BigInteger value = programContext.getValue(register, address, false);
			strings[i] = "assume " + register.getName() + " = 0x" + value.toString(16);
		}
		return strings;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		Object obj = bf.getProxy().getObject();
		if ((obj instanceof Function) && loc.getClass() == RegisterFieldLocation.class) {
			RegisterFieldLocation regLoc = (RegisterFieldLocation) loc;
			return new FieldLocation(index, fieldNum, regLoc.getRow(), regLoc.getCharOffset());
		}
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (obj instanceof Function) {
			Function function = (Function) obj;
			List<Register> setRegisters = getSetRegisters(function);
			String[] registerStrings = getRegisterStrings(function, setRegisters);
			String[] registerNames = getRegisterNames(setRegisters);
			return new RegisterFieldLocation(function.getProgram(), function.getEntryPoint(),
				registerNames, registerStrings, row, col);
		}
		return null;
	}

	private String[] getRegisterNames(List<Register> setRegisters) {
		String[] names = new String[setRegisters.size()];
		for (int i = 0; i < names.length; i++) {
			names[i] = setRegisters.get(i).getName();
		}
		return names;
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!Function.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.FUNCTION);
	}

	@Override
	public Color getDefaultColor() {
		return OptionsGui.REGISTERS.getDefaultColor();
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.fieldOptionsChanged(options, optionName, oldValue, newValue);

		if (optionName.equals(DISPLAY_HIDDEN_REGISTERS_OPTION_NAME)) {
			showHiddenRegisters = (Boolean) newValue;
			model.update();
		}

		if (optionName.equals(DISPLAY_DEFAULT_REGISTER_VALUES_OPTION_NAME)) {
			showDefaultValues = (Boolean) newValue;
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

	private List<Register> getSetRegisters(Function function) {
		Program program = function.getProgram();
		ProgramContext programContext = program.getProgramContext();
		Register[] registers = programContext.getRegistersWithValues();
		Address address = function.getEntryPoint();
		List<Register> setRegisters = new ArrayList<>();
		for (Register register : registers) {
			if (register.isHidden() && !showHiddenRegisters) {
				continue;
			}

			RegisterValue regVal =
				showDefaultValues ? programContext.getRegisterValue(register, address)
						: programContext.getNonDefaultValue(register, address);

			if (regVal != null && regVal.hasValue()) {
				setRegisters.add(register);
			}
		}
		if (setRegisters.size() > 1) {
			List<Register> dedupedRegisters = new ArrayList<>();
			for (Register register : setRegisters) {
				Register parent = register.getParentRegister();
				if (parent == null || !setRegisters.contains(parent)) {
					dedupedRegisters.add(register);
				}
			}
			setRegisters = dedupedRegisters;
		}
		Collections.sort(setRegisters, regComp);
		return setRegisters;
	}

	private FieldElement[] getFieldElements(String[] registerStrings) {
		FieldElement[] fieldElements = new FieldElement[registerStrings.length];
		for (int i = 0; i < registerStrings.length; i++) {
			AttributedString str = new AttributedString(registerStrings[i], regColor, getMetrics());
			fieldElements[i] = new TextFieldElement(str, i, 0);
		}
		return fieldElements;
	}

	private ListingTextField getTextField(String[] registerStrings, ProxyObj<?> proxy, int xStart) {
		if (registerStrings.length <= 0) {
			return null;
		}

		FieldElement[] fieldElements = getFieldElements(registerStrings);
		return ListingTextField.createMultilineTextField(this, proxy, fieldElements, xStart, width,
			Integer.MAX_VALUE, hlProvider);
	}

	private class RegComparator implements Comparator<Register> {
		@Override
		public int compare(Register r1, Register r2) {
			return r1.getName().compareToIgnoreCase(r2.getName());
		}

	}
}
