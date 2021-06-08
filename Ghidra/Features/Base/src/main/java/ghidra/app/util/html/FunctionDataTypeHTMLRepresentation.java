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
package ghidra.app.util.html;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.ToolTipUtils;
import ghidra.app.util.datatype.DataTypeUrl;
import ghidra.app.util.html.diff.DataTypeDiff;
import ghidra.app.util.html.diff.DataTypeDiffBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.util.HTMLUtilities;
import ghidra.util.StringUtilities;
import ghidra.util.exception.AssertException;

public class FunctionDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {

	private static final int MAX_LINE_COUNT = 10;

	protected TextLine returnType;
	protected TextLine functionName;

	protected List<ValidatableLine> arguments;
	protected TextLine varArgs;
	protected TextLine voidArgs;

	private static String truncatedHtmlData;

	// private constructor for making diff copies
	private FunctionDataTypeHTMLRepresentation(TextLine returnType, TextLine functionName,
			List<ValidatableLine> arguments, TextLine varArgs, TextLine voidArgs) {
		this.returnType = returnType;
		this.functionName = functionName;
		this.arguments = arguments;
		this.varArgs = varArgs;
		this.voidArgs = voidArgs;

		originalHTMLData =
			buildHTMLText(returnType, functionName, arguments, varArgs, voidArgs, false);
		truncatedHtmlData =
			buildHTMLText(returnType, functionName, arguments, varArgs, voidArgs, true);
	}

	public FunctionDataTypeHTMLRepresentation(FunctionDefinition functionDefinition) {
		returnType = buildReturnType(functionDefinition);
		functionName = buildName(functionDefinition);
		arguments = buildArguments(functionDefinition);
		varArgs = buildVarArgs(functionDefinition);
		voidArgs = buildVoidArgs(functionDefinition);

		originalHTMLData =
			buildHTMLText(returnType, functionName, arguments, varArgs, voidArgs, false);
		truncatedHtmlData =
			buildHTMLText(returnType, functionName, arguments, varArgs, voidArgs, true);
	}

	// overridden to return truncated text by default
	@Override
	public String getHTMLString() {
		return HTML_OPEN + truncatedHtmlData + HTML_CLOSE;
	}

	// overridden to return truncated text by default
	@Override
	public String getHTMLContentString() {
		return truncatedHtmlData;
	}

	@Override
	protected PlaceHolderLine createPlaceHolderLine(ValidatableLine oppositeLine) {
		if (!(oppositeLine instanceof VariableTextLine)) {
			throw new AssertException("I didn't know you could pass me other types of lines?!");
		}
		VariableTextLine variableTextLine = (VariableTextLine) oppositeLine;
		int stringLength = variableTextLine.getVariableType().length() +
			variableTextLine.getVariableName().length();
		return new EmptyVariableTextLine(stringLength);
	}

	private TextLine buildVarArgs(FunctionDefinition functionDefinition) {
		if (functionDefinition.hasVarArgs()) {
			return new TextLine(FunctionSignature.VAR_ARGS_DISPLAY_STRING);
		}
		return new TextLine("");
	}

	private TextLine buildVoidArgs(FunctionDefinition functionDefinition) {
		if (functionDefinition.getArguments().length == 0 && !functionDefinition.hasVarArgs()) {
			return new TextLine(FunctionSignature.VOID_PARAM_DISPLAY_STRING);
		}
		return new TextLine("");
	}

	private TextLine buildName(FunctionDefinition functionDefinition) {
		return new TextLine(HTMLUtilities.friendlyEncodeHTML(functionDefinition.getDisplayName()));
	}

	private TextLine buildReturnType(FunctionDefinition functionDefinition) {
		DataType returnDataType = functionDefinition.getReturnType();
		GenericCallingConvention genericCallingConvention =
			functionDefinition.getGenericCallingConvention();
		String modifier = genericCallingConvention != GenericCallingConvention.unknown
				? (" " + genericCallingConvention.getDeclarationName())
				: "";
		return new TextLine(
			HTMLUtilities.friendlyEncodeHTML(returnDataType.getDisplayName()) + modifier);
	}

	// display name to name pairs
	private List<ValidatableLine> buildArguments(FunctionDefinition functionDefinition) {
		ParameterDefinition[] vars = functionDefinition.getArguments();
		List<ValidatableLine> lines = new ArrayList<>(vars.length);
		for (ParameterDefinition var : vars) {
			DataType dataType = var.getDataType();
			String displayName = dataType.getDisplayName();
			String name = var.getName();

			DataType locatableType = getLocatableDataType(dataType);
			lines.add(new VariableTextLine(HTMLUtilities.friendlyEncodeHTML(displayName),
				HTMLUtilities.friendlyEncodeHTML(name), locatableType));
		}

		return lines;
	}

	private static String buildHTMLText(TextLine returnType, TextLine functionName,
			List<ValidatableLine> arguments, TextLine varArgs, TextLine voidArgs, boolean trim) {

		StringBuilder fullHtml = new StringBuilder();
		StringBuilder truncatedHtml = new StringBuilder();

		int lineCount = 0;
		String returnTypeText = returnType.getText();
		if (trim) {
			returnTypeText =
				StringUtilities.trimMiddle(returnTypeText, ToolTipUtils.LINE_LENGTH);
		}
		returnTypeText = wrapStringInColor(returnTypeText, returnType.getTextColor());

		String functionNameText = functionName.getText();
		if (trim) {
			functionNameText =
				StringUtilities.trimMiddle(functionNameText, ToolTipUtils.LINE_LENGTH);
		}
		functionNameText = wrapStringInColor(functionNameText, functionName.getTextColor());

		//@formatter:off
		append(fullHtml, truncatedHtml, lineCount, returnTypeText,
                                                   HTML_SPACE,
                                                   functionNameText,
                                                   "(");
		//@formatter:on

		String varArgsText = varArgs.getText();
		varArgsText = wrapStringInColor(varArgsText, varArgs.getTextColor());
		boolean hasVarArgs = varArgsText.length() != 0;

		int size = arguments.size();
		for (int i = 0; i < size; i++, lineCount++) { // walk in pairs (display name to name)
			append(fullHtml, truncatedHtml, lineCount, BR);

			VariableTextLine variableLine = (VariableTextLine) arguments.get(i);
			String typeText = generateTypeText(variableLine, trim);
			String variableNameText = variableLine.getVariableName();
			if (trim) {
				variableNameText =
					StringUtilities.trimMiddle(variableNameText, ToolTipUtils.LINE_LENGTH);
			}
			variableNameText =
				wrapStringInColor(variableNameText, variableLine.getVariableNameColor());

			String separator = "";
			if ((i < size - 1) || (size > 0 && hasVarArgs)) {
				separator = ",";
			}

			//@formatter:off
			append(fullHtml, truncatedHtml, lineCount, TAB, 
                                                       typeText,
                                                       HTML_SPACE,
                                                       variableNameText,
                                                       separator);
			//@formatter:on
		}

		if (hasVarArgs) {
			if (size > 0) {

				//@formatter:off
				append(fullHtml, truncatedHtml, lineCount, BR, 
                                                           TAB);
				//@formatter:on
				lineCount++;
			}

			append(fullHtml, truncatedHtml, lineCount, varArgsText);
		}
		else if (size == 0) {
			String voidArgsText = voidArgs.getText();
			voidArgsText = wrapStringInColor(voidArgsText, voidArgs.getTextColor());
			if (voidArgsText.length() != 0) {
				append(fullHtml, truncatedHtml, lineCount, varArgsText);
			}
		}

		if (lineCount >= MAX_LINE_COUNT) {
			truncatedHtml.append(ELLIPSES);
		}

		fullHtml.append(")").append(BR);
		truncatedHtml.append(")").append(BR);

		if (trim) {
			return truncatedHtml.toString();
		}
		return fullHtml.toString();
	}

	private static void append(StringBuilder fullHtml, StringBuilder truncatedHtml,
			int lineCount, String... content) {

		for (String string : content) {
			fullHtml.append(string);
			truncatedHtml.append(string);
		}
	}

	private static String generateTypeText(VariableTextLine line, boolean trim) {

		String type = line.getVariableType();
		if (trim) {
			type = StringUtilities.trimMiddle(type, ToolTipUtils.LINE_LENGTH);
		}
		type = wrapStringInColor(type, line.getVariableTypeColor());

		if (!line.hasUniversalId()) {
			return type;
		}

		//
		// Markup the name with info for later hyperlink capability, as needed by the client
		//
		DataType dataType = line.getDataType();
		DataTypeUrl url = new DataTypeUrl(dataType);
		String wrapped = HTMLUtilities.wrapWithLinkPlaceholder(type, url.toString());
		return wrapped;
	}

	@Override
	public HTMLDataTypeRepresentation[] diff(HTMLDataTypeRepresentation otherRepresentation) {
		if (this == otherRepresentation) {
			return new HTMLDataTypeRepresentation[] { this, this };
		}

		if (!(otherRepresentation instanceof FunctionDataTypeHTMLRepresentation)) {
			// completely different, make it as such
			return new HTMLDataTypeRepresentation[] {
				new CompletelyDifferentHTMLDataTypeRepresentationWrapper(this),
				new CompletelyDifferentHTMLDataTypeRepresentationWrapper(otherRepresentation) };
		}

		FunctionDataTypeHTMLRepresentation functionRepresentation =
			(FunctionDataTypeHTMLRepresentation) otherRepresentation;

		TextLine diffReturnType = new TextLine(returnType.getText());
		TextLine diffFunctionName = new TextLine(functionName.getText());
		List<ValidatableLine> argumentLines = copyLines(arguments);
		TextLine diffVarArgs = new TextLine(varArgs.getText());
		TextLine diffVoidArgs = new TextLine(voidArgs.getText());

		TextLine otherDiffReturnType = new TextLine(functionRepresentation.returnType.getText());
		TextLine otherDiffFunctionName =
			new TextLine(functionRepresentation.functionName.getText());
		List<ValidatableLine> otherArgumentLines = copyLines(functionRepresentation.arguments);
		TextLine otherDiffVarArgs = new TextLine(functionRepresentation.varArgs.getText());
		TextLine otherDiffVoidArgs = new TextLine(functionRepresentation.voidArgs.getText());

		diffTextLine(diffReturnType, otherDiffReturnType);
		diffTextLine(diffFunctionName, otherDiffFunctionName);

		HTMLDataTypeRepresentationDiffInput diffInput =
			new HTMLDataTypeRepresentationDiffInput(this, argumentLines);
		HTMLDataTypeRepresentationDiffInput otherDiffInput =
			new HTMLDataTypeRepresentationDiffInput(otherRepresentation, otherArgumentLines);

		DataTypeDiff argumentsDiff = DataTypeDiffBuilder.diffBody(diffInput, otherDiffInput);

		diffTextLine(diffVarArgs, otherDiffVarArgs);
		diffTextLine(diffVoidArgs, otherDiffVoidArgs);

		return new HTMLDataTypeRepresentation[] {
			new FunctionDataTypeHTMLRepresentation(diffReturnType, diffFunctionName,
				argumentsDiff.getLeftLines(), diffVarArgs, diffVoidArgs),
			new FunctionDataTypeHTMLRepresentation(otherDiffReturnType, otherDiffFunctionName,
				argumentsDiff.getRightLines(), otherDiffVarArgs, otherDiffVoidArgs) };
	}
}
