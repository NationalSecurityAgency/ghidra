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

import javax.swing.event.ChangeListener;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InvalidPrototype;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.MnemonicFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
  *  Generates Mnemonic Fields.
  */
public class MnemonicFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "Mnemonic";
	public static final Color OVERRIDE_COLOR = new Color(180, 0, 108);
// TODO: Should BAD_PROTOTYPE_COLOR be an option?
	private final static Color BAD_PROTOTYPE_COLOR = new Color(196, 0, 0);
	private final static String SHOW_UNDERLINE_FOR_REFERENCES =
		GhidraOptions.MNEMONIC_GROUP_TITLE + Options.DELIMITER + "Underline Fields With References";

	private static final String OVERRIDE_COLOR_OPTION = "Mnemonic, Override Color";
	private Color overrideColor;
	private boolean underliningEnabled = true;

	protected BrowserCodeUnitFormat codeUnitFormat;
	private ChangeListener codeUnitFormatListener = e -> MnemonicFieldFactory.this.model.update();

	/**
	 * Default constructor.
	 */
	public MnemonicFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hsProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private MnemonicFieldFactory(FieldFormatModel model, HighlightProvider hsProvider,
			Options displayOptions, ToolOptions fieldOptions) {
		super(FIELD_NAME, model, hsProvider, displayOptions, fieldOptions);

		overrideColor = displayOptions.getColor(OVERRIDE_COLOR_OPTION, OVERRIDE_COLOR);

		HelpLocation hl = new HelpLocation("CodeBrowserPlugin", "Mnemonic_Field");
		fieldOptions.getOptions("Mnemonic Fields").setOptionsHelpLocation(hl);

		fieldOptions.registerOption(SHOW_UNDERLINE_FOR_REFERENCES, true, hl,
			"Shows an underline on mnemonic " + "fields that have references.");
		underliningEnabled = fieldOptions.getBoolean(SHOW_UNDERLINE_FOR_REFERENCES, true);

		// Create code unit format and associated options - listen for changes
		codeUnitFormat = new BrowserCodeUnitFormat(fieldOptions, true);
		codeUnitFormat.addChangeListener(codeUnitFormatListener);
	}

	@Override
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(OVERRIDE_COLOR_OPTION)) {
			overrideColor = (Color) newValue;
		}
		super.displayOptionsChanged(options, optionName, oldValue, newValue);
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(SHOW_UNDERLINE_FOR_REFERENCES)) {
			underliningEnabled = ((Boolean) newValue).booleanValue();
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
		boolean invalidInstrProto = false;
		if (cu instanceof Instruction) {
			invalidInstrProto = (((Instruction) cu).getPrototype() instanceof InvalidPrototype);
		}

		boolean underline = underliningEnabled && (cu.getMnemonicReferences().length > 0);
		String mnemonic = codeUnitFormat.getMnemonicRepresentation(cu);
		Color c = color;
		if (invalidInstrProto) {
			c = BAD_PROTOTYPE_COLOR;
		}
		else if (cu instanceof Instruction) {
			Instruction instr = (Instruction) cu;
			if (instr.getFlowOverride() != FlowOverride.NONE || instr.isFallThroughOverridden()) {
				c = overrideColor;
			}
		}
		else {
			Data data = (Data) cu;
			if (data.isDefined() && data.getDataType().isNotYetDefined()) {
				c = Color.RED;
			}
		}
		AttributedString as =
			new AttributedString(mnemonic, c, getMetrics(), underline, underlineColor);
		FieldElement text = new TextFieldElement(as, 0, 0);
		return ListingTextField.createSingleLineTextField(this, proxy, text, startX + varWidth,
			width, hlProvider);
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;

		int[] cpath = null;
		if (cu instanceof Data) {
			cpath = ((Data) cu).getComponentPath();
		}

		Address referenceAddress = getReferenceAddress(cu);

		String mnemonic = codeUnitFormat.getMnemonicRepresentation(cu);
		return new MnemonicFieldLocation(cu.getProgram(), cu.getMinAddress(), referenceAddress,
			cpath, mnemonic, col);
	}

	private Address getReferenceAddress(CodeUnit cu) {

		Program program = cu.getProgram();

		if (cu instanceof Data) {
			if (((Data) cu).getNumComponents() != 0) {
				return null; // outer composite/array type should ignore reference from component
			}
		}

		ReferenceManager referenceManager = program.getReferenceManager();
		Reference[] referencesFrom = referenceManager.getReferencesFrom(cu.getMinAddress());
		for (Reference reference : referencesFrom) {
			if (reference.isMemoryReference()) {
				return reference.getToAddress();
			}
		}

		return null;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {

		if (!(programLoc instanceof MnemonicFieldLocation)) {
			return null;
		}
		if (!hasSamePath(bf, programLoc)) {
			return null;
		}
		MnemonicFieldLocation loc = (MnemonicFieldLocation) programLoc;
		return new FieldLocation(index, fieldNum, 0, loc.getCharOffset());
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!CodeUnit.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA ||
			category == FieldFormatModel.OPEN_DATA);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider hsProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new MnemonicFieldFactory(formatModel, hsProvider, displayOptions, fieldOptions);
	}

	@Override
	public Color getDefaultColor() {
		return OptionsGui.MNEMONIC.getDefaultColor();
	}
}
