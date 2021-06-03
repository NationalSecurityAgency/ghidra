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

import docking.widgets.fieldpanel.field.AttributedString;
import docking.widgets.fieldpanel.field.TextFieldElement;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.FunctionProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.FunctionSignatureSourceFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
  *  Generates Function Signature Source Fields.
  */
public class FunctionSignatureSourceFieldFactory extends FieldFactory {

	public static final String FIELD_NAME = "Signature Source";
//	private Color funRetColor;
	private Color literalColor;

	//private int displayWidth;

	/**
	 * Default Constructor
	 */
	public FunctionSignatureSourceFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	public FunctionSignatureSourceFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);

		literalColor = displayOptions.getColor(OptionsGui.SEPARATOR.getColorOptionName(),
			OptionsGui.SEPARATOR.getDefaultColor());
	}

	@Override
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.displayOptionsChanged(options, optionName, oldValue, newValue);
		literalColor = options.getColor(OptionsGui.SEPARATOR.getColorOptionName(), Color.BLACK);
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		if (!enabled) {
			return null;
		}
		if (proxy instanceof FunctionProxy) {
			FunctionProxy functionProxy = (FunctionProxy) proxy;
			Function function = functionProxy.getObject();
			SourceType source = function.getSignatureSource();
			String sourceStr = "<" + source.toString() + ">";
			AttributedString as = new AttributedString(sourceStr, literalColor, getMetrics());
			return ListingTextField.createSingleLineTextField(this, proxy,
				new TextFieldElement(as, 0, 0), startX + varWidth, width, hlProvider);
		}
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		ProxyObj<?> proxy = bf.getProxy();
		if (proxy instanceof FunctionProxy) {
			FunctionProxy functionProxy = (FunctionProxy) proxy;
			Function function = functionProxy.getObject();
			return new FunctionSignatureSourceFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				function.getSignatureSource().toString(), col);
		}

		return null;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		if (loc instanceof FunctionSignatureSourceFieldLocation) {
			FunctionSignatureSourceFieldLocation sigSourceLoc =
				(FunctionSignatureSourceFieldLocation) loc;
			return new FieldLocation(index, fieldNum, 0, sigSourceLoc.getCharOffset());
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
		return new FunctionSignatureSourceFieldFactory(formatModel, provider, displayOptions,
			fieldOptions);
	}

	@Override
	public Color getDefaultColor() {
		return OptionsGui.SEPARATOR.getDefaultColor();
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		// don't care
	}
}
