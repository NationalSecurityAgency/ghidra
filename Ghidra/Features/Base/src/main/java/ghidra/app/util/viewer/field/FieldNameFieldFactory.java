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

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.data.Array;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.util.FieldNameFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
  *  Generates Data Field (structure field names and array indexes) name Fields.
  */
public class FieldNameFieldFactory extends FieldFactory {

	public static final String FIELD_NAME = "Field Name";

	public final static String ARRAY_INDEX_FORMAT_NAME =
		FormatManager.ARRAY_OPTIONS_GROUP + Options.DELIMITER + "Array Index Format";

	public static enum IndexFormat {

		decimal(10, "", ""), hex(16, "0x", ""), octal(8, "0", ""), binary(2, "", "b");

		final int radix;
		final String prefix;
		final String postfix;

		IndexFormat(int radix, String prefix, String postfix) {
			this.radix = radix;
			this.prefix = prefix;
			this.postfix = postfix;
		}
	}

	private IndexFormat format;

	public FieldNameFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private FieldNameFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, ToolOptions fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
		fieldOptions.registerOption(ARRAY_INDEX_FORMAT_NAME, IndexFormat.decimal, null,
			"Hex or Decimal field offsets for arrays");
		format = fieldOptions.getEnum(ARRAY_INDEX_FORMAT_NAME, IndexFormat.decimal);
	}

	private String getFieldName(Data data) {
		Data parent = data.getParent();
		if (parent != null && (parent.getDataType() instanceof Array)) {
			String indexStr = format.prefix +
				Integer.toString(data.getComponentIndex(), format.radix) + format.postfix;
			return "[" + indexStr + "]";
		}
		return data.getFieldName();
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.fieldOptionsChanged(options, optionName, oldValue, newValue);

		if (options.getName().equals(GhidraOptions.CATEGORY_BROWSER_FIELDS)) {
			if (optionName.equals(ARRAY_INDEX_FORMAT_NAME)) {
				format = (IndexFormat) newValue;
				model.update();
			}
		}
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof Data)) {
			return null;
		}
		Data data = (Data) obj;

		String fieldName = getFieldName(data);
		if ((fieldName == null) || (fieldName.length() == 0)) {
			return null;
		}
		AttributedString as = new AttributedString(fieldName, color, getMetrics());
		FieldElement text = new TextFieldElement(as, 0, 0);

		return ListingTextField.createSingleLineTextField(this, proxy, text, startX + varWidth,
			width, hlProvider);
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof Data)) {
			return null;
		}
		Data data = (Data) obj;
		return new FieldNameFieldLocation(data.getProgram(), data.getMinAddress(),
			data.getComponentPath(), getFieldName(data), col);
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {
		if (!(programLoc instanceof FieldNameFieldLocation)) {
			return null;
		}
		FieldNameFieldLocation loc = (FieldNameFieldLocation) programLoc;
		if (!hasSamePath(bf, loc)) {
			return null;
		}
		return new FieldLocation(index, fieldNum, 0, loc.getCharOffset());

	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!CodeUnit.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.OPEN_DATA || category == FieldFormatModel.ARRAY);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider provider,
			ToolOptions toolOptions, ToolOptions fieldOptions) {
		return new FieldNameFieldFactory(formatModel, provider, toolOptions, fieldOptions);
	}

	@Override
	public Color getDefaultColor() {
		return OptionsGui.FIELD_NAME.getDefaultColor();
	}
}
