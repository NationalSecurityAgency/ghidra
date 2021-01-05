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

import ghidra.app.util.datatype.DataTypeUrl;
import ghidra.app.util.html.diff.DataTypeDiff;
import ghidra.app.util.html.diff.DataTypeDiffBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.AssertException;

public class FunctionDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {
	protected TextLine returnType;
	protected TextLine functionName;

	protected List<ValidatableLine> arguments;
	protected TextLine varArgs;
	protected TextLine voidArgs;

	// private constructor for making diff copies
	private FunctionDataTypeHTMLRepresentation(TextLine returnType, TextLine functionName,
			List<ValidatableLine> arguments, TextLine varArgs, TextLine voidArgs) {
		this.returnType = returnType;
		this.functionName = functionName;
		this.arguments = arguments;
		this.varArgs = varArgs;
		this.voidArgs = voidArgs;
		originalHTMLData = buildHTMLText(returnType, functionName, arguments, varArgs, voidArgs);
	}

	public FunctionDataTypeHTMLRepresentation(FunctionDefinition functionDefinition) {
		returnType = buildReturnType(functionDefinition);
		functionName = buildName(functionDefinition);
		arguments = buildArguments(functionDefinition);
		varArgs = buildVarArgs(functionDefinition);
		voidArgs = buildVoidArgs(functionDefinition);
		originalHTMLData = buildHTMLText(returnType, functionName, arguments, varArgs, voidArgs);
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
				? (" " + genericCallingConvention.name())
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
			List<ValidatableLine> arguments, TextLine varArgs, TextLine voidArgs) {

		StringBuilder sb = new StringBuilder();

		String returnTypeText = returnType.getText();
		returnTypeText = wrapStringInColor(returnTypeText, returnType.getTextColor());

		String functionNameText = functionName.getText();
		functionNameText = wrapStringInColor(functionNameText, functionName.getTextColor());

		sb.append(returnTypeText).append(HTML_SPACE).append(functionNameText).append("(");

		String varArgsText = varArgs.getText();
		varArgsText = wrapStringInColor(varArgsText, varArgs.getTextColor());
		boolean hasVarArgs = varArgsText.length() != 0;

		int size = arguments.size();
		for (int i = 0; i < size; i++) { // walk in pairs (display name to name)
			sb.append(BR);
			VariableTextLine variableLine = (VariableTextLine) arguments.get(i);

			String typeText = generateTypeText(variableLine);

			String variableNameText = variableLine.getVariableName();
			variableNameText =
				wrapStringInColor(variableNameText, variableLine.getVariableNameColor());

			sb.append(TAB).append(typeText).append(HTML_SPACE).append(variableNameText);

			if ((i + 1 < size - 1) || (size > 0 && hasVarArgs)) {
				sb.append(",");
			}
			if (i > MAX_COMPONENTS) {
// TODO: change to diff color if any of the ellipsed-out args are diffed
				// if ( cointains unmatching lines ( arguments, i ) )
				// then make the ellipses the diff color
				sb.append(TAB).append(ELLIPSES).append(BR);
				break;
			}
		}

		if (hasVarArgs) {
			if (size > 0) {
				sb.append(BR).append(TAB);
			}
			sb.append(varArgsText);
		}
		else if (size == 0) {
			String voidArgsText = voidArgs.getText();
			voidArgsText = wrapStringInColor(voidArgsText, voidArgs.getTextColor());
			if (voidArgsText.length() != 0) {
				sb.append(voidArgsText);
			}
		}

		sb.append(")").append(BR);

		return sb.toString();
	}

	private static String generateTypeText(VariableTextLine line) {

		String type = line.getVariableType();
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
