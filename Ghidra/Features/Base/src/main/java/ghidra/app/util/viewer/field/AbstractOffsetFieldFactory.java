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

import java.math.BigInteger;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.theme.GColor;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

/**
 *  Generates Offset fields
 */
public abstract class AbstractOffsetFieldFactory extends FieldFactory {

	public static final GColor COLOR = new GColor("color.fg.listing.field.offset");

	private static final String SHOW_NAME = "Show Name";
	private static final String USE_HEX = "Use Hex";
	private static final boolean DEFAULT_SHOW_NAME = false;
	private static final boolean DEFAULT_USE_HEX = true;

	protected boolean showName;
	protected boolean useHex;

	protected String fieldName;
	protected String groupTitle;


	/**
	 * Creates a new {@link AbstractOffsetFieldFactory}
	 * 
	 * @param offsetDescription A description of the offset
	 */
	public AbstractOffsetFieldFactory(String offsetDescription) {
		super(offsetDescription + " Offset");
	}

	/**
	 * Creates a new {@link AbstractOffsetFieldFactory}
	 * 
	 * @param offsetDescription A description of the field offset
	 * @param nameDescription A description of the name that can get prepended to the field offset
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	protected AbstractOffsetFieldFactory(String offsetDescription, String nameDescription,
			FieldFormatModel model, ListingHighlightProvider hlProvider, Options displayOptions,
			Options fieldOptions) {
		super(offsetDescription + " Offset", model, hlProvider, displayOptions, fieldOptions);
		fieldName = offsetDescription + " Offset";
		groupTitle = offsetDescription + " Offset Field";
		initOptions(fieldOptions, offsetDescription, nameDescription);
	}

	/**
	 * Gets the offset value
	 * 
	 * @param codeUnit The {@link CodeUnit}
	 * @return The offset value
	 */
	public abstract String getOffsetValue(CodeUnit codeUnit);

	/**
	 * Gets the {@link OffsetFieldType offset type}
	 * 
	 * @return the {@link OffsetFieldType offset type}
	 */
	public abstract OffsetFieldType getOffsetFieldType();

	private void initOptions(Options fieldOptions, String offsetDescription,
			String nameDescription) {
		HelpLocation helpLoc =
			new HelpLocation("CodeBrowserPlugin", offsetDescription + "_Offset_Field");
		fieldOptions.getOptions(groupTitle).setOptionsHelpLocation(helpLoc);

		fieldOptions.registerOption(getFullOptionName(SHOW_NAME), DEFAULT_SHOW_NAME, helpLoc,
			"Prepends the %s name to the %s offset in the offset field."
					.formatted(nameDescription.toLowerCase(), offsetDescription));
		fieldOptions.registerOption(getFullOptionName(USE_HEX), DEFAULT_USE_HEX, helpLoc,
			"Toggles displaying offsets in hexadecimal/decimal in the offset field.");

		showName = fieldOptions.getBoolean(getFullOptionName(SHOW_NAME), DEFAULT_SHOW_NAME);
		useHex = fieldOptions.getBoolean(getFullOptionName(USE_HEX), DEFAULT_USE_HEX);
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof CodeUnit)) {
			return null;
		}
		FieldElement fieldElement = new TextFieldElement(
			new AttributedString(getOffsetValue((CodeUnit) obj), COLOR, getMetrics()), 0, 0);
		ListingTextField listingTextField = ListingTextField.createSingleLineTextField(this, proxy,
			fieldElement, startX + varWidth, width, hlProvider);
		listingTextField.setPrimary(true);
		return listingTextField;
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionsName, Object oldValue,
			Object newValue) {
		if (optionsName.equals(getFullOptionName(SHOW_NAME))) {
			showName = ((Boolean) newValue).booleanValue();
			model.update();
		}
		else if (optionsName.equals(getFullOptionName(USE_HEX))) {
			useHex = ((Boolean) newValue).booleanValue();
			model.update();
		}
	}

	@Override
	public FieldLocation getFieldLocation(ListingField lf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		if (loc instanceof OffsetFieldLocation offsetLoc &&
			offsetLoc.getType().equals(getOffsetFieldType())) {
			Object obj = lf.getProxy().getObject();

			if (obj instanceof CodeUnit && hasSamePath(lf, offsetLoc)) {
				return new FieldLocation(index, fieldNum, 0, offsetLoc.getCharOffset());
			}
		}
		return null;
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
		return new OffsetFieldLocation(cu.getProgram(), addr, cpath, col, getOffsetFieldType());
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!CodeUnit.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA ||
			category == FieldFormatModel.OPEN_DATA || category == FieldFormatModel.ARRAY);
	}

	/**
	 * Gets the full option name, which includes the group and options delimiter
	 * 
	 * @param shortName The short option name (no group or options delimiter)
	 * @return The full option name, which includes the group and options delimiter
	 */
	private String getFullOptionName(String shortName) {
		return groupTitle + Options.DELIMITER + shortName;
	}
}
