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
import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.util.AddressFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;

public class ArrayValuesFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "Array Values";
	private int valuesPerLine;

	public ArrayValuesFieldFactory() {
		super(FIELD_NAME);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel,
			ListingHighlightProvider highlightProvider, ToolOptions toolOptions,
			ToolOptions fieldOptions) {
		return new ArrayValuesFieldFactory(formatModel, highlightProvider, toolOptions,
			fieldOptions);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private ArrayValuesFieldFactory(FieldFormatModel model, ListingHighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
		setupOptions(fieldOptions);
	}

	private void setupOptions(Options fieldOptions) {
		// we need to install a custom editor that allows us to edit a group of related options
		fieldOptions.registerOption(FormatManager.ARRAY_DISPLAY_OPTIONS, OptionType.CUSTOM_TYPE,
			new ArrayElementWrappedOption(), null, FormatManager.ARRAY_DISPLAY_DESCRIPTION,
			() -> new ArrayElementPropertyEditor());
		CustomOption wrappedOption = fieldOptions.getCustomOption(
			FormatManager.ARRAY_DISPLAY_OPTIONS, new ArrayElementWrappedOption());

		HelpLocation hl = new HelpLocation("CodeBrowserPlugin", "Array_Options");
		fieldOptions.getOptions(FormatManager.ARRAY_OPTIONS_GROUP).setOptionsHelpLocation(hl);
		fieldOptions.getOptions(FormatManager.ARRAY_DISPLAY_OPTIONS).setOptionsHelpLocation(hl);

		if (!(wrappedOption instanceof ArrayElementWrappedOption)) {
			throw new AssertException("Someone set an option for " +
				FormatManager.ARRAY_DISPLAY_OPTIONS + " that is not the expected " +
				"ghidra.app.util.viewer.field.NamespaceWrappedOption type.");
		}

		ArrayElementWrappedOption arrayElementOption = (ArrayElementWrappedOption) wrappedOption;
		valuesPerLine = arrayElementOption.getArrayElementsPerLine();
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof Data)) {
			return null;
		}
		Data data = (Data) obj;
		Data parent = data.getParent();
		int numComponents = parent.getNumComponents();
		int index = data.getComponentIndex();
		int remaining = numComponents - index;
		int itemCount = Math.min(remaining, valuesPerLine);
		boolean isLastLine = remaining <= itemCount;

		FieldElement[] aStrings = new FieldElement[itemCount];
		for (int i = 0; i < itemCount; i++) {
			Data child = parent.getComponent(index++);
			boolean isLastItem = isLastLine && (i == itemCount - 1);
			String value = getDisplayValue(child, !isLastItem);
			AttributedString as =
				new AttributedString(value, ListingColors.ARRAY_VALUES, getMetrics());
			aStrings[i] = new TextFieldElement(as, i, 0);
		}
		return ListingTextField.createPackedTextField(this, proxy, aStrings, startX + varWidth,
			width, 1, hlProvider);

	}

	private String getDisplayValue(Data data, boolean addDelimeter) {
		DataType dt = data.getDataType();
		int minLength = data.getLength() * 3 + 1;  // this just seems a decent minimum size
		StringBuffer buf = new StringBuffer(dt.getRepresentation(data, data, data.getLength()));
		if (buf.length() < minLength) {
			for (int i = buf.length(); i < minLength; i++) {
				buf.insert(0, ' ');
			}
		}
		if (addDelimeter) {
			buf.append(',');
		}
		return buf.toString();
	}

	@Override
	public FieldLocation getFieldLocation(ListingField lf, BigInteger index, int fieldNum,
			ProgramLocation location) {

		// Unless the location is specifically targeting the address field, then we should
		// process the location because the arrays display is different from all other format
		// models in that one line actually represents more than one array data element. So
		// this field has the best chance of representing the location for array data elements.

		if (location instanceof AddressFieldLocation) {
			return null;
		}

		RowColLocation rcl = getDataRowColumnLocation(location, lf);
		return new FieldLocation(index, fieldNum, rcl.row(), rcl.col());
	}

	private RowColLocation getDataRowColumnLocation(ProgramLocation location, ListingField field) {
		ListingTextField ltf = (ListingTextField) field;
		Data firstDataOnLine = (Data) field.getProxy().getObject();

		if (location instanceof ArrayElementFieldLocation loc) {
			int elementIndex = loc.getElementIndexOnLine(firstDataOnLine);
			return ltf.dataToScreenLocation(elementIndex, loc.getCharOffset());
		}

		Address byteAddress = location.getByteAddress();
		int byteOffset = (int) byteAddress.subtract(firstDataOnLine.getAddress());
		int componentSize = firstDataOnLine.getLength();
		int elementOffset = byteOffset / componentSize;
		return ltf.dataToScreenLocation(elementOffset, 0);
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField listingField) {
		if (!(listingField instanceof ListingTextField)) {
			return null;
		}
		Data data = (Data) listingField.getProxy().getObject();
		ListingTextField btf = (ListingTextField) listingField;
		RowColLocation loc = btf.screenToDataLocation(row, col);
		int arrayIndex = data.getComponentIndex() + loc.row();

		Data arrayElement = data.getParent().getComponent(arrayIndex);
		Program program = data.getProgram();
		return new ArrayElementFieldLocation(program, arrayElement.getMinAddress(),
			arrayElement.getComponentPath(), getDisplayValue(arrayElement, false), loc.row(),
			loc.col());
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!CodeUnit.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.ARRAY);
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {

		if (optionName.equals(FormatManager.ARRAY_DISPLAY_OPTIONS)) {
			CustomOption customOption = options.getCustomOption(FormatManager.ARRAY_DISPLAY_OPTIONS,
				new ArrayElementWrappedOption());

			if (!(customOption instanceof ArrayElementWrappedOption)) {
				throw new AssertException("Someone set an option for " +
					FormatManager.ARRAY_DISPLAY_OPTIONS + " that is not the expected " +
					"ghidra.app.util.viewer.field.NamespaceWrappedOption type.");
			}

			ArrayElementWrappedOption arrayElementOption = (ArrayElementWrappedOption) customOption;
			valuesPerLine = arrayElementOption.getArrayElementsPerLine();
		}
	}

}
