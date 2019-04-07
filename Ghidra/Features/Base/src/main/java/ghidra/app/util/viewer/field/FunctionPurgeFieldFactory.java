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
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.util.FunctionPurgeFieldLocation;
import ghidra.program.util.ProgramLocation;

public class FunctionPurgeFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "Function Purge";

	public FunctionPurgeFieldFactory() {
		super(FIELD_NAME);
	}

	private FunctionPurgeFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
		color = displayOptions.getColor(OptionsGui.BYTES.getColorOptionName(),
			OptionsGui.BYTES.getDefaultColor());

	}

	@Override
	public FieldFactory newInstance(FieldFormatModel newModel, HighlightProvider newHlProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new FunctionPurgeFieldFactory(newModel, newHlProvider, displayOptions, fieldOptions);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getField(ProxyObj, int)
	 */
	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof Function)) {
			return null;
		}
		Function func = (Function) obj;

		String stringDepth = "UNK";
		int depth = func.getStackPurgeSize();
		switch (depth) {
			case Function.INVALID_STACK_DEPTH_CHANGE:
				stringDepth = "INV";
				break;
			case Function.UNKNOWN_STACK_DEPTH_CHANGE:
				stringDepth = "UNK";
				break;
			default:
				if (depth < 0) {
					stringDepth = "-" + Integer.toHexString(-depth);
				}
				else {
					stringDepth = Integer.toHexString(depth);
				}
		}
		AttributedString as = new AttributedString(stringDepth, Color.BLUE, getMetrics());
		FieldElement text = new TextFieldElement(as, 0, 0);
		return ListingTextField.createSingleLineTextField(this, proxy, text, startX + varWidth,
			width, hlProvider);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		if (loc instanceof FunctionPurgeFieldLocation) {
			FunctionPurgeFieldLocation functionPurgeLoc = (FunctionPurgeFieldLocation) loc;
			return new FieldLocation(index, fieldNum, 0, functionPurgeLoc.getCharOffset());
		}
		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getProgramLocation(int, int, ghidra.app.util.viewer.field.ListingField)
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof Function) || row < 0 || col < 0) {
			return null;
		}

		Function func = (Function) obj;

		return new FunctionPurgeFieldLocation(func.getProgram(), func.getEntryPoint(), col);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#acceptsType(int, java.lang.Class)
	 */
	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!Function.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.FUNCTION);
	}

}
