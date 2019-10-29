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
import java.beans.PropertyEditor;
import java.math.BigInteger;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;

/**
  *  Generates Address Fields.
  */
public class AddressFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "Address";
	public static final Color DEFAULT_COLOR = Color.BLACK;
	private final static String GROUP_TITLE = "Address Field";
	public final static String DISPLAY_BLOCK_NAME =
		GROUP_TITLE + Options.DELIMITER + "Display Block Name";
	public final static String ADDRESS_DISPLAY_OPTIONS_NAME =
		GROUP_TITLE + Options.DELIMITER + "Address Display Options";
	private boolean displayBlockName;
	private boolean padZeros;
	private int minHexDigits;
	private boolean rightJustify;
	private PropertyEditor addressFieldOptionsEditor = new AddressFieldOptionsPropertyEditor();

	/**
	 * Default Constructor
	 */
	public AddressFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private AddressFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
		initOptions(fieldOptions);
	}

	private void initOptions(Options fieldOptions) {
		HelpLocation helpLoc = new HelpLocation("CodeBrowserPlugin", "Address_Field");

		fieldOptions.registerOption(ADDRESS_DISPLAY_OPTIONS_NAME, OptionType.CUSTOM_TYPE,
			new AddressFieldOptionsWrappedOption(), helpLoc, "Adjusts the Address Field display",
			addressFieldOptionsEditor);

		CustomOption customOption =
			fieldOptions.getCustomOption(ADDRESS_DISPLAY_OPTIONS_NAME, null);

		if (!(customOption instanceof AddressFieldOptionsWrappedOption)) {
			throw new AssertException("Someone set an option for " + ADDRESS_DISPLAY_OPTIONS_NAME +
				" that is not the expected " + AddressFieldOptionsWrappedOption.class.getName() +
				" type.");
		}
		AddressFieldOptionsWrappedOption afowo = (AddressFieldOptionsWrappedOption) customOption;
		padZeros = afowo.padWithZeros();
		minHexDigits = afowo.getMinimumHexDigits();
		displayBlockName = afowo.showBlockName();
		rightJustify = afowo.rightJustify();

		fieldOptions.getOptions(GROUP_TITLE).setOptionsHelpLocation(helpLoc);
	}

	@Override
	public Color getDefaultColor() {
		return DEFAULT_COLOR;
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionsName, Object oldValue,
			Object newValue) {
		if (optionsName.equals(ADDRESS_DISPLAY_OPTIONS_NAME)) {
			AddressFieldOptionsWrappedOption afowo = (AddressFieldOptionsWrappedOption) newValue;
			padZeros = afowo.padWithZeros();
			minHexDigits = afowo.getMinimumHexDigits();
			displayBlockName = afowo.showBlockName();
			rightJustify = afowo.rightJustify();
			model.update();
		}
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {

		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;
		String text = getAddressString(cu);
		FieldElement as =
			new TextFieldElement(new AttributedString(text, color, getMetrics()), 0, 0);
		ListingTextField ltf;
		if (rightJustify) {
			ltf = ListingTextField.createSingleLineTextFieldWithReverseClipping(this, proxy, as,
				startX + varWidth, width, hlProvider);
		}
		else {
			ltf = ListingTextField.createSingleLineTextField(this, proxy, as, startX + varWidth,
				width, hlProvider);
		}
		ltf.setPrimary(true);

		return ltf;
	}

	private String getAddressString(CodeUnit cu) {
		Address addr = cu.getMinAddress();
		AddressSpace space = addr.getAddressSpace();
		if (displayBlockName) {
			String text = addr.toString(false, padZeros ? 16 : minHexDigits);
			MemoryBlock block = cu.getProgram().getMemory().getBlock(addr);
			if (block != null) {
				return block.getName() + ":" + text;
			}
		}
		return addr.toString(space.showSpaceName(), padZeros ? 16 : minHexDigits);
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField lf) {
		Object obj = lf.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;

		Address addr = cu.getMinAddress();

		int[] cpath = null;
		if (cu instanceof Data) {
			cpath = ((Data) cu).getComponentPath();
		}

		return new AddressFieldLocation(cu.getProgram(), addr, cpath, addr.toString(), col);
	}

	@Override
	public FieldLocation getFieldLocation(ListingField lf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		Object obj = lf.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}

		if (loc.getClass() == ProgramLocation.class) {
			if (loc.getComponentPath() == null || hasSamePath(lf, loc)) {
				return new FieldLocation(index, fieldNum, 0, 0);
			}
		}
		else if (loc.getClass() == CodeUnitLocation.class) {
			return new FieldLocation(index, fieldNum, 0, 0);
		}
		else if (loc instanceof AddressFieldLocation) {
			if (hasSamePath(lf, loc)) {
				return new FieldLocation(index, fieldNum, 0,
					((AddressFieldLocation) loc).getCharOffset());
			}
		}
		return null;
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!CodeUnit.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA ||
			category == FieldFormatModel.OPEN_DATA || category == FieldFormatModel.ARRAY);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel newModel,
			HighlightProvider highlightStringProvider, ToolOptions toolOptions,
			ToolOptions fieldOptions) {
		return new AddressFieldFactory(newModel, highlightStringProvider, toolOptions,
			fieldOptions);
	}
}
