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

import java.awt.*;

import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.field.ListingColors.FunctionColors;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.options.ScreenElement;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;

public abstract class AbstractVariableFieldFactory extends FieldFactory {

	private static class ParameterFieldOptions {
		private final ScreenElement element;
		FontMetrics defaultMetrics;
		FontMetrics[] fontMetrics = new FontMetrics[4];
		int style = -1;

		ParameterFieldOptions(ScreenElement element) {
			this.element = element;
		}

		String getStyleOptionName() {
			return element.getStyleOptionName();
		}
	}

	private static final int CUSTOM_PARAM_INDEX = 0;
	private static final int DYNAMIC_PARAM_INDEX = 1;

	private ParameterFieldOptions[] parameterFieldOptions;

	/**
	 * Constructs a AbstractVariableFieldFactory with given name.  Used only as potential field.
	 * @param name the name of the field.
	 */
	public AbstractVariableFieldFactory(String name) {
		super(name);
	}

	/**
	 * AbstractVariableFieldFactory constructor
	 * @param name the name of the field
	 * @param model the model that the field belongs to.
	 * @param highlightProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	protected AbstractVariableFieldFactory(String name, FieldFormatModel model,
			ListingHighlightProvider highlightProvider, Options displayOptions, Options fieldOptions) {
		super(name, model, highlightProvider, displayOptions, fieldOptions);
	}

	protected void initDisplayOptions(Options displayOptions) {

		// display options for local variables handled by FieldFactory base class
		colorOptionName = "Variable Color";
		styleOptionName = "Variable Style";

		super.initDisplayOptions(displayOptions);

		parameterFieldOptions = new ParameterFieldOptions[2];
		parameterFieldOptions[CUSTOM_PARAM_INDEX] =
			new ParameterFieldOptions(OptionsGui.PARAMETER_CUSTOM);
		parameterFieldOptions[DYNAMIC_PARAM_INDEX] =
			new ParameterFieldOptions(OptionsGui.PARAMETER_DYNAMIC);

		for (int i = 0; i < 2; i++) {
			parameterFieldOptions[i].style =
				displayOptions.getInt(parameterFieldOptions[i].getStyleOptionName(), -1);
			setMetrics(baseFont, parameterFieldOptions[i]);
		}
	}

	@Override
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {

		if (optionName.equals(FONT_OPTION_NAME)) {
			baseFont = (Font) newValue;
			setMetrics(baseFont, parameterFieldOptions[CUSTOM_PARAM_INDEX]);
			setMetrics(baseFont, parameterFieldOptions[DYNAMIC_PARAM_INDEX]);
		}
		else {
			for (int i = 0; i < 2; i++) {
				if (optionName.equals(styleOptionName)) {
					parameterFieldOptions[i].style = options.getInt(optionName, -1);
					setMetrics(baseFont, parameterFieldOptions[i]);
				}
			}
		}
		super.displayOptionsChanged(options, optionName, oldValue, newValue);
	}

	@SuppressWarnings("deprecation")
	// we know
	private void setMetrics(Font newFont, ParameterFieldOptions paramFieldOptions) {
		paramFieldOptions.defaultMetrics = Toolkit.getDefaultToolkit().getFontMetrics(newFont);
		for (int i = 0; i < paramFieldOptions.fontMetrics.length; i++) {
			Font font = newFont.deriveFont(i); // i is looping over the 4 font styles PLAIN, BOLD, ITALIC, and BOLDITALIC
			paramFieldOptions.fontMetrics[i] = Toolkit.getDefaultToolkit().getFontMetrics(font);
		}
	}

	protected Color getColor(Variable var) {
		if (var instanceof Parameter) {
			return var.getFunction().hasCustomVariableStorage() ? FunctionColors.PARAM_CUSTOM
					: FunctionColors.PARAM_DYNAMIC;
		}
		return FunctionColors.PARAM;
	}

	protected FontMetrics getMetrics(Variable var) {
		if (var instanceof Parameter) {
			int index = var.getFunction().hasCustomVariableStorage() ? CUSTOM_PARAM_INDEX
					: DYNAMIC_PARAM_INDEX;
			int fontStyle = parameterFieldOptions[index].style;
			return fontStyle == -1 ? parameterFieldOptions[index].defaultMetrics
					: parameterFieldOptions[index].fontMetrics[fontStyle];
		}
		return getMetrics();
	}

}
