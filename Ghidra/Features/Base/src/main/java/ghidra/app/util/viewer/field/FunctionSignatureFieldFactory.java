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
import java.util.List;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.GhidraOptions;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.FunctionProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;

/**
  *  Generates FunctionSignature Fields.
  */
public class FunctionSignatureFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "Function Signature";

	public final static String GROUP_TITLE = "Function Signature Field";
	public final static String DISPLAY_NAMESPACE =
		GROUP_TITLE + Options.DELIMITER + GhidraOptions.DISPLAY_NAMESPACE;

	private boolean displayFunctionScope;
	private Color funNameColor;
	private Color unresolvedThunkRefColor;
	private Color resolvedThunkRefColor;
	private Color funRetColor;
	private Color literalColor;
	private Color funParamsColor;
	private Color autoParamColor;

	/**
	 * Default Constructor
	 */
	public FunctionSignatureFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	public FunctionSignatureFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);

		fieldOptions.registerOption(DISPLAY_NAMESPACE, false, null,
			"Prepends namespaces to labels that are not in the global namespace.");

		displayFunctionScope = fieldOptions.getBoolean(DISPLAY_NAMESPACE, false);

		funRetColor = displayOptions.getColor(OptionsGui.FUN_RET_TYPE.getColorOptionName(),
			OptionsGui.FUN_RET_TYPE.getDefaultColor());
		funNameColor = displayOptions.getColor(OptionsGui.FUN_NAME.getColorOptionName(),
			OptionsGui.FUN_NAME.getDefaultColor());
		unresolvedThunkRefColor =
			displayOptions.getColor(OptionsGui.BAD_REF_ADDR.getColorOptionName(),
				OptionsGui.BAD_REF_ADDR.getDefaultColor());
		resolvedThunkRefColor =
			displayOptions.getColor(OptionsGui.EXT_REF_RESOLVED.getColorOptionName(),
				OptionsGui.EXT_REF_RESOLVED.getDefaultColor());
		funParamsColor = displayOptions.getColor(OptionsGui.FUN_PARAMS.getColorOptionName(),
			OptionsGui.FUN_PARAMS.getDefaultColor());
		autoParamColor = displayOptions.getColor(OptionsGui.FUN_AUTO_PARAMS.getColorOptionName(),
			OptionsGui.FUN_PARAMS.getDefaultColor());
		literalColor = displayOptions.getColor(OptionsGui.SEPARATOR.getColorOptionName(),
			OptionsGui.SEPARATOR.getDefaultColor());
	}

	@Override
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.displayOptionsChanged(options, optionName, oldValue, newValue);
		funRetColor = options.getColor(OptionsGui.FUN_RET_TYPE.getColorOptionName(), Color.BLACK);
		funNameColor = options.getColor(OptionsGui.FUN_NAME.getColorOptionName(), Color.BLACK);
		unresolvedThunkRefColor =
			displayOptions.getColor(OptionsGui.BAD_REF_ADDR.getColorOptionName(),
				OptionsGui.BAD_REF_ADDR.getDefaultColor());
		resolvedThunkRefColor =
			displayOptions.getColor(OptionsGui.EXT_REF_RESOLVED.getColorOptionName(),
				OptionsGui.EXT_REF_RESOLVED.getDefaultColor());
		funParamsColor = options.getColor(OptionsGui.FUN_PARAMS.getColorOptionName(), Color.BLACK);
		autoParamColor =
			options.getColor(OptionsGui.FUN_AUTO_PARAMS.getColorOptionName(), Color.GRAY);
		literalColor = options.getColor(OptionsGui.SEPARATOR.getColorOptionName(), Color.BLACK);
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof Function)) {
			return null;
		}

		Function function = (Function) obj;
		Parameter[] params = function.getParameters();
		ArrayList<FieldElement> textElements = new ArrayList<>();
		int elementIndex = 0;
		AttributedString as;
		int startCol = 0; // Column in the function signature where the current element will start.

		// inline
		if (function.isInline()) {
			as = new AttributedString(Function.INLINE + " ", funRetColor, getMetrics());
			textElements.add(new FunctionInlineFieldElement(as, elementIndex, 0, startCol));
			startCol += as.length();
			elementIndex++;
		}

		// thunk
		if (function.isThunk()) {
			as = new AttributedString(Function.THUNK + " ", funRetColor, getMetrics());
			textElements.add(new FunctionThunkFieldElement(as, elementIndex, 0, startCol));
			startCol += as.length();
			elementIndex++;
		}

		// noreturn
		if (function.hasNoReturn()) {
			as = new AttributedString(Function.NORETURN + " ", funRetColor, getMetrics());
			textElements.add(new FunctionNoReturnFieldElement(as, elementIndex, 0, startCol));
			startCol += as.length();
			elementIndex++;
		}

		// return type
		as = new AttributedString(function.getReturn().getFormalDataType().getDisplayName() + " ",
			funRetColor, getMetrics());
		textElements.add(new FunctionReturnTypeFieldElement(as, elementIndex, 0, startCol));
		startCol += as.length();
		elementIndex++;

		// calling convention
		String callingConvention = function.getCallingConventionName();
		if (callingConvention.equals(Function.DEFAULT_CALLING_CONVENTION_STRING)) {
			callingConvention = function.getCallingConvention().getName();
		}
		if (callingConvention != null &&
			!callingConvention.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING)) {
			as = new AttributedString(callingConvention + " ", funRetColor, getMetrics());
			textElements.add(
				new FunctionCallingConventionFieldElement(as, elementIndex, 0, startCol));
			startCol += as.length();
			elementIndex++;
		}

		// function name
		as = new AttributedString(function.getName(displayFunctionScope),
			getFunctionNameColor(function), getMetrics());
		textElements.add(new FunctionNameFieldElement(as, elementIndex, 0, startCol));
		startCol += as.length();
		elementIndex++;

		// opening parenthesis
		as = new AttributedString("(", literalColor, getMetrics());
		textElements.add(new FunctionStartParametersFieldElement(as, elementIndex, 0, startCol));
		startCol += as.length();
		elementIndex++;

		// parameters
		int paramOffset = 0;
		AttributedString commaSeparator = new AttributedString(", ", literalColor, getMetrics());
		int lastParam = params.length - 1;
		for (int i = 0; i < params.length; i++) {

			// do not display auto-params in signature
//			if (params[i].isAutoParameter()) {
//				continue;
//			}

			Color pcolor = params[i].isAutoParameter() ? autoParamColor : funParamsColor;

			String text = params[i].getFormalDataType().getDisplayName() + " ";
			as = new AttributedString(text, pcolor, getMetrics());
			textElements.add(
				new FunctionParameterFieldElement(as, elementIndex, paramOffset, startCol, i));
			startCol += as.length();
			paramOffset += as.length();
			elementIndex++;

			text = params[i].getName();
			as = new AttributedString(text, pcolor, getMetrics());
			textElements.add(
				new FunctionParameterNameFieldElement(as, elementIndex, paramOffset, startCol, i));
			startCol += as.length();
			paramOffset += as.length();
			elementIndex++;

			if (i != lastParam) { // separator
				textElements.add(
					new FunctionSignatureFieldElement(commaSeparator, elementIndex, 0, startCol));
				startCol += commaSeparator.length();
				paramOffset += commaSeparator.length();
				elementIndex++;
			}
		}

		// varargs
		if (function.hasVarArgs()) {
			if (params.length > 0) {
				textElements.add(
					new FunctionSignatureFieldElement(commaSeparator, elementIndex, 0, startCol));
				startCol += commaSeparator.length();
				paramOffset += commaSeparator.length();
				elementIndex++;
			}
			as = new AttributedString(FunctionSignature.VAR_ARGS_DISPLAY_STRING, funParamsColor,
				getMetrics());
			textElements.add(new FunctionSignatureFieldElement(as, elementIndex, 0, startCol));
			startCol += as.length();
			elementIndex++;
		}
		else if (lastParam < 0 && function.getSignatureSource() != SourceType.DEFAULT) {
			// void parameter list
			as = new AttributedString(FunctionSignature.VOID_PARAM_DISPLAY_STRING, funParamsColor,
				getMetrics());
			textElements.add(new FunctionSignatureFieldElement(as, elementIndex, 0, startCol));
			startCol += as.length();
			elementIndex++;
		}

		// closing parenthesis
		as = new AttributedString(")", literalColor, getMetrics());
		textElements.add(new FunctionEndParametersFieldElement(as, elementIndex, 0, startCol));

		return ListingTextField.createSingleLineTextField(this, proxy,
			new CompositeFieldElement(textElements), startX + varWidth, width, hlProvider);
	}

	private Color getFunctionNameColor(Function function) {
		// override function name color for external thunks which are not linked
		if (function.isThunk()) {
			Function thunkedFunction = function.getThunkedFunction(true);
			if (thunkedFunction == null) {
				return unresolvedThunkRefColor;
			}
			else if (thunkedFunction.isExternal()) {
				ExternalLocation externalLocation = thunkedFunction.getExternalLocation();
				String libName = externalLocation.getLibraryName();
				if (Library.UNKNOWN.equals(libName)) {
					return unresolvedThunkRefColor;
				}
				ExternalManager externalManager = function.getProgram().getExternalManager();
				String path = externalManager.getExternalLibraryPath(libName);
				if (path == null || path.length() == 0) {
					return unresolvedThunkRefColor;
				}
				return resolvedThunkRefColor;
			}
		}
		return funNameColor;
	}

	@Override
	public ProgramLocation getProgramLocation(int fieldRow, int fieldColumn,
			ListingField listingField) {
		ProxyObj<?> proxy = listingField.getProxy();

		if (proxy instanceof FunctionProxy) {
			FunctionProxy functionProxy = (FunctionProxy) proxy;

			if (!(listingField instanceof ListingTextField)) {
				return null;
			}

			ListingTextField btf = (ListingTextField) listingField;
			FieldElement fe = btf.getFieldElement(fieldRow, fieldColumn);
			if (!(fe instanceof FunctionSignatureFieldElement)) {
				return null;
			}
			FunctionSignatureFieldElement fieldElement = (FunctionSignatureFieldElement) fe;
			int offset = fieldElement.getOffsetInFieldElement(fieldColumn);
			if (offset == -1) {
				return null;
			}
			RowColLocation rowCol = fieldElement.getDataLocationForCharacterIndex(offset);
			return fieldElement.getProgramLocation(functionProxy, listingField.getText(),
				rowCol.row(), rowCol.col());
		}

		return null;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (loc instanceof FunctionSignatureFieldLocation) {
			FunctionSignatureFieldLocation signatureLocation = (FunctionSignatureFieldLocation) loc;
			if (signatureLocation.isFieldBasedPositioning()) {
				return getFieldBasedFunctionSignatureFieldLocation(signatureLocation, bf, index,
					fieldNum);
			}
			return new FieldLocation(index, fieldNum, 0, signatureLocation.getCharOffset());
		}
		return null;
	}

	private FieldLocation getFieldBasedFunctionSignatureFieldLocation(
			FunctionSignatureFieldLocation signatureLocation, ListingField bf, BigInteger index,
			int fieldNum) {

		int characterIndex = 0;
		List<FieldElement> elements = getFieldElements(bf);
		if (signatureLocation instanceof FunctionNameFieldLocation) {
			characterIndex =
				getFunctionSignatureElement(elements, FunctionNameFieldElement.class, 0);
		}
		else if (signatureLocation instanceof FunctionReturnTypeFieldLocation) {
			characterIndex =
				getFunctionSignatureElement(elements, FunctionReturnTypeFieldElement.class, 0);
		}
		else if (signatureLocation instanceof FunctionInlineFieldLocation) {
			characterIndex =
				getFunctionSignatureElement(elements, FunctionInlineFieldElement.class, 0);
		}
		else if (signatureLocation instanceof FunctionNoReturnFieldLocation) {
			characterIndex =
				getFunctionSignatureElement(elements, FunctionNoReturnFieldElement.class, 0);
		}
		else if (signatureLocation instanceof FunctionParameterNameFieldLocation) {
			FunctionParameterNameFieldLocation parameterNameLocation =
				(FunctionParameterNameFieldLocation) signatureLocation;
			int ordinal = parameterNameLocation.getOrdinal();
			characterIndex = getFunctionSignatureElement(elements,
				FunctionParameterNameFieldElement.class, ordinal);
		}
		else if (signatureLocation instanceof FunctionStartParametersFieldLocation) {
			characterIndex =
				getFunctionSignatureElement(elements, FunctionStartParametersFieldElement.class, 0);
		}
		else if (signatureLocation instanceof FunctionEndParametersFieldLocation) {
			characterIndex =
				getFunctionSignatureElement(elements, FunctionEndParametersFieldElement.class, 0);
		}

		return new FieldLocation(index, fieldNum, 0, characterIndex);
	}

	private int getFunctionSignatureElement(List<FieldElement> elements, Class<?> elementClass,
			int classIndex) {

		int characterCount = 0;
		int classCount = 0;
		for (FieldElement fieldElement : elements) {
			if (fieldElement.getClass() == elementClass) {
				if (classCount == classIndex) {
					return characterCount;
				}
				classCount++;
			}
			characterCount += fieldElement.getText().length();
		}
		return 0;
	}

	private List<FieldElement> getFieldElements(ListingField listingField) {
		TextField textField = (TextField) listingField;
		List<FieldElement> elements = new ArrayList<>();
		int numRows = textField.getNumRows();
		for (int row = 0; row < numRows; row++) {
			FieldElement previousFieldElement = null;
			int numColumns = textField.getNumCols(row);
			for (int col = 0; col < numColumns; col++) {
				FieldElement fieldElement = textField.getFieldElement(row, col);
				if (fieldElement == null) {
					break;
				}
				if (fieldElement != previousFieldElement) {
					elements.add(fieldElement);
					previousFieldElement = fieldElement;
				}
			}
		}
		return elements;
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
		return new FunctionSignatureFieldFactory(formatModel, provider, displayOptions,
			fieldOptions);
	}

	@Override
	public Color getDefaultColor() {
		return OptionsGui.FUN_NAME.getDefaultColor();
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {

		if (optionName.equals(DISPLAY_NAMESPACE)) {
			displayFunctionScope = ((Boolean) newValue).booleanValue();
			model.update();
		}
	}

//==================================================================================================
// Support FieldElement classes
//==================================================================================================
	class FunctionSignatureFieldElement extends AbstractTextFieldElement {
		int functionSigIndex;

		/**
		 * A field element of the function signature field. The individual elements that compose
		 * a function signature should extend this class.
		 * @param as the attributed string used to display this element.
		 * @param row the row of the function signature where this field element starts.
		 * @param column the column where this field element starts within the row.
		 */
		FunctionSignatureFieldElement(AttributedString as, int row, int column,
				int functionSigIndex) {
			super(as, row, column);
			this.functionSigIndex = functionSigIndex;
		}

		ProgramLocation getProgramLocation(FunctionProxy functionProxy, String signature,
				int fieldRow, int fieldColumn) {
			int offsetIndex = getCharacterIndexForDataLocation(fieldRow, fieldColumn);
			if (offsetIndex < 0) {
				return null;
			}

			int signatureIndex = offsetIndex + functionSigIndex;
			Function function = functionProxy.getObject();
			return new FunctionSignatureFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				signatureIndex, signature);
		}

		FieldElement createElement(AttributedString as, int elementRow, int elementColumn,
				int signatureIndex) {
			return new FunctionSignatureFieldElement(as, elementRow, elementColumn, signatureIndex);
		}

		int getOffsetInFieldElement(int signatureIndex) {
			int offset = signatureIndex - functionSigIndex;
			if (offset >= 0 && offset <= length()) {
				return offset;
			}
			return -1;
		}

		@Override
		public FieldElement substring(int start, int end) {
			AttributedString as = attributedString.substring(start, end);
			if (as == attributedString) {
				return this;
			}
			return createElement(as, row, column, functionSigIndex + start);
		}

		@Override
		public FieldElement replaceAll(char[] targets, char replacement) {
			return createElement(attributedString.replaceAll(targets, replacement), row, column,
				functionSigIndex);
		}
	}

	class FunctionReturnTypeFieldElement extends FunctionSignatureFieldElement {
		FunctionReturnTypeFieldElement(AttributedString as, int row, int column,
				int functionSigIndex) {
			super(as, row, column, functionSigIndex);
		}

		@Override
		ProgramLocation getProgramLocation(FunctionProxy functionProxy, String signature,
				int rowInField, int columnInRow) {
			Function function = functionProxy.getObject();
			int signatureIndex =
				getCharacterIndexForDataLocation(rowInField, columnInRow) + functionSigIndex;
			return new FunctionReturnTypeFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				signatureIndex, signature, function.getReturnType().getName());
		}

		@Override
		FieldElement createElement(AttributedString as, int elementRow, int elementColumn,
				int signatureIndex) {
			return new FunctionReturnTypeFieldElement(as, elementRow, elementColumn,
				signatureIndex);
		}
	}

	class FunctionInlineFieldElement extends FunctionSignatureFieldElement {
		FunctionInlineFieldElement(AttributedString as, int elementRow, int elementColumn,
				int functionSigIndex) {
			super(as, elementRow, elementColumn, functionSigIndex);
		}

		@Override
		ProgramLocation getProgramLocation(FunctionProxy functionProxy, String signature,
				int rowInField, int columnInRow) {
			Function function = functionProxy.getObject();
			int signatureIndex =
				getCharacterIndexForDataLocation(rowInField, columnInRow) + functionSigIndex;
			return new FunctionInlineFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				signatureIndex, signature);
		}

		@Override
		FieldElement createElement(AttributedString as, int elementRow, int elementColumn,
				int signatureIndex) {
			return new FunctionInlineFieldElement(as, elementRow, elementColumn, signatureIndex);
		}
	}

	class FunctionThunkFieldElement extends FunctionSignatureFieldElement {
		FunctionThunkFieldElement(AttributedString as, int elementRow, int elementColumn,
				int functionSigIndex) {
			super(as, elementRow, elementColumn, functionSigIndex);
		}

		@Override
		ProgramLocation getProgramLocation(FunctionProxy functionProxy, String signature,
				int rowInField, int columnInRow) {
			Function function = functionProxy.getObject();
			int signatureIndex =
				getCharacterIndexForDataLocation(rowInField, columnInRow) + functionSigIndex;
			return new FunctionThunkFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				signatureIndex, signature);
		}

		@Override
		FieldElement createElement(AttributedString as, int elementRow, int elementColumn,
				int signatureIndex) {
			return new FunctionInlineFieldElement(as, elementRow, elementColumn, signatureIndex);
		}
	}

	class FunctionNoReturnFieldElement extends FunctionSignatureFieldElement {
		FunctionNoReturnFieldElement(AttributedString as, int elementRow, int elementColumn,
				int functionSigIndex) {
			super(as, elementRow, elementColumn, functionSigIndex);
		}

		@Override
		ProgramLocation getProgramLocation(FunctionProxy functionProxy, String signature,
				int rowInField, int columnInRow) {
			Function function = functionProxy.getObject();
			int signatureIndex =
				getCharacterIndexForDataLocation(rowInField, columnInRow) + functionSigIndex;
			return new FunctionNoReturnFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				signatureIndex, signature, (function.isInline() ? Function.NORETURN : ""));
		}

		@Override
		FieldElement createElement(AttributedString as, int elementRow, int elementColumn,
				int signatureIndex) {
			return new FunctionNoReturnFieldElement(as, elementRow, elementColumn, signatureIndex);
		}
	}

	class FunctionCallingConventionFieldElement extends FunctionSignatureFieldElement {
		FunctionCallingConventionFieldElement(AttributedString as, int elementRow,
				int elementColumn, int functionSigIndex) {
			super(as, elementRow, elementColumn, functionSigIndex);
		}

		@Override
		ProgramLocation getProgramLocation(FunctionProxy functionProxy, String signature,
				int rowInField, int columnInRow) {
			Function function = functionProxy.getObject();
			int signatureIndex =
				getCharacterIndexForDataLocation(rowInField, columnInRow) + functionSigIndex;
			return new FunctionCallingConventionFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				signatureIndex, signature);
		}

		@Override
		FieldElement createElement(AttributedString as, int elementRow, int elementColumn,
				int signatureIndex) {
			return new FunctionCallingConventionFieldElement(as, elementRow, elementColumn,
				signatureIndex);
		}
	}

	class FunctionNameFieldElement extends FunctionSignatureFieldElement {
		FunctionNameFieldElement(AttributedString as, int row, int column, int functionSigIndex) {
			super(as, row, column, functionSigIndex);
		}

		@Override
		ProgramLocation getProgramLocation(FunctionProxy functionProxy, String signature,
				int rowInField, int columnInRow) {
			Function function = functionProxy.getObject();
			int signatureIndex =
				getCharacterIndexForDataLocation(rowInField, columnInRow) + functionSigIndex;
			return new FunctionNameFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				signatureIndex, signature, function.getName(displayFunctionScope));
		}

		@Override
		FieldElement createElement(AttributedString as, int elementRow, int columnInRow,
				int signatureIndex) {
			return new FunctionNameFieldElement(as, elementRow, columnInRow, signatureIndex);
		}
	}

	class FunctionStartParametersFieldElement extends FunctionSignatureFieldElement {
		FunctionStartParametersFieldElement(AttributedString as, int elementRow, int columnInRow,
				int functionSigIndex) {
			super(as, elementRow, columnInRow, functionSigIndex);
		}

		@Override
		ProgramLocation getProgramLocation(FunctionProxy functionProxy, String signature,
				int rowInField, int columnInRow) {
			Function function = functionProxy.getObject();
			int signatureIndex =
				getCharacterIndexForDataLocation(rowInField, columnInRow) + functionSigIndex;
			return new FunctionStartParametersFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				signatureIndex, signature);
		}

		@Override
		FieldElement createElement(AttributedString as, int elementRow, int columnInRow,
				int signatureIndex) {
			return new FunctionNameFieldElement(as, elementRow, columnInRow, signatureIndex);
		}
	}

	class FunctionEndParametersFieldElement extends FunctionSignatureFieldElement {
		FunctionEndParametersFieldElement(AttributedString as, int row, int column,
				int functionSigIndex) {
			super(as, row, column, functionSigIndex);
		}

		@Override
		ProgramLocation getProgramLocation(FunctionProxy functionProxy, String signature,
				int rowInField, int columnInRow) {
			Function function = functionProxy.getObject();
			int signatureIndex =
				getCharacterIndexForDataLocation(rowInField, columnInRow) + functionSigIndex;
			return new FunctionEndParametersFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				signatureIndex, signature);
		}

		@Override
		FieldElement createElement(AttributedString as, int elementRow, int columnInRow,
				int signatureIndex) {
			return new FunctionNameFieldElement(as, elementRow, columnInRow, signatureIndex);
		}
	}

	class FunctionParameterFieldElement extends FunctionSignatureFieldElement {
		protected final int parameterOrdinal;

		FunctionParameterFieldElement(AttributedString as, int row, int column,
				int functionSigIndex, int parameterOrdinal) {
			super(as, row, column, functionSigIndex);
			this.parameterOrdinal = parameterOrdinal;
		}

		@Override
		ProgramLocation getProgramLocation(FunctionProxy functionProxy, String signature,
				int rowInField, int columnInRow) {
			Function function = functionProxy.getObject();
			int signatureIndex =
				getCharacterIndexForDataLocation(rowInField, columnInRow) + functionSigIndex;
			return new FunctionParameterFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				signatureIndex, signature, function.getParameter(parameterOrdinal));
		}

		@Override
		FieldElement createElement(AttributedString as, int elementRow, int columnInRow,
				int signatureIndex) {
			return new FunctionParameterFieldElement(as, elementRow, columnInRow, signatureIndex,
				parameterOrdinal);
		}
	}

	class FunctionParameterNameFieldElement extends FunctionParameterFieldElement {

		FunctionParameterNameFieldElement(AttributedString as, int row, int column,
				int functionSigIndex, int parameterOrdinal) {
			super(as, row, column, functionSigIndex, parameterOrdinal);
		}

		@Override
		ProgramLocation getProgramLocation(FunctionProxy functionProxy, String signature,
				int rowInField, int columnInRow) {
			Function function = functionProxy.getObject();
			int signatureIndex =
				getCharacterIndexForDataLocation(rowInField, columnInRow) + functionSigIndex;
			return new FunctionParameterNameFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				signatureIndex, signature, function.getParameter(parameterOrdinal));
		}

		@Override
		FieldElement createElement(AttributedString as, int elementRow, int columnInRow,
				int signatureIndex) {
			return new FunctionParameterNameFieldElement(as, elementRow, columnInRow,
				signatureIndex, parameterOrdinal);
		}
	}

	// TODO: if we ever need a VarArgs handler, put one here
}
