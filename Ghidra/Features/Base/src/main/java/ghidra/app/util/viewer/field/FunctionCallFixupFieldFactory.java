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

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.FunctionProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.util.FunctionCallFixupFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
  *  Generates Function Call-Fixup Fields.
  */
public class FunctionCallFixupFieldFactory extends FieldFactory {

	public static final String FIELD_NAME = "Function Call-Fixup";
	private Color fixupColor;
	private Color literalColor;

	/**
	 * Default Constructor
	 */
	public FunctionCallFixupFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	public FunctionCallFixupFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);

		literalColor = displayOptions.getColor(OptionsGui.SEPARATOR.getColorOptionName(),
			OptionsGui.SEPARATOR.getDefaultColor());
		fixupColor = displayOptions.getColor(OptionsGui.FUN_CALL_FIXUP.getColorOptionName(),
			OptionsGui.FUN_CALL_FIXUP.getDefaultColor());
	}

	@Override
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.displayOptionsChanged(options, optionName, oldValue, newValue);
		literalColor = options.getColor(OptionsGui.FUN_CALL_FIXUP.getColorOptionName(),
			OptionsGui.FUN_CALL_FIXUP.getDefaultColor());
		fixupColor = options.getColor(OptionsGui.FUN_CALL_FIXUP.getColorOptionName(),
			OptionsGui.FUN_CALL_FIXUP.getDefaultColor());
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof Function)) {
			return null;
		}
		Function f = (Function) obj;
		String callFixupStr = f.getCallFixup();
		if (callFixupStr == null) {
			return null;
		}

		ArrayList<FieldElement> textElements = new ArrayList<>();
		AttributedString as;
		int elementIndex = 0;

		as = new AttributedString("Call-Fixup: ", literalColor, getMetrics());
		textElements.add(new TextFieldElement(as, elementIndex++, 0));

		as = new AttributedString(callFixupStr, fixupColor, getMetrics());
		textElements.add(new TextFieldElement(as, elementIndex++, 0));

		return ListingTextField.createSingleLineTextField(this, proxy,
			new CompositeFieldElement(textElements), startX + varWidth, width, hlProvider);
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		ProxyObj<?> proxy = bf.getProxy();
		if (proxy instanceof FunctionProxy) {
			FunctionProxy functionProxy = (FunctionProxy) proxy;
			Function function = functionProxy.getObject();
			return new FunctionCallFixupFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				function.getCallFixup(), col);
		}

		return null;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (loc instanceof FunctionCallFixupFieldLocation) {
			FunctionCallFixupFieldLocation callFixupLoc = (FunctionCallFixupFieldLocation) loc;
			return new FieldLocation(index, fieldNum, 0, callFixupLoc.getCharOffset());
		}
		return null;
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!Function.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.FUNCTION);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider provider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new FunctionCallFixupFieldFactory(formatModel, provider, displayOptions,
			fieldOptions);
	}

	@Override
	public Color getDefaultColor() {
		return OptionsGui.FUN_CALL_FIXUP.getDefaultColor();
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		// don't care
	}
}
