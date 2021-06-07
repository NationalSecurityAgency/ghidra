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
package ghidra.app.util;

import static ghidra.util.HTMLUtilities.*;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.html.*;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.StringUtilities;

/**
 * A utility class that creates tool tip text for given data types.
 * 
 * 
 * @since Tracker Id 616
 */
public class ToolTipUtils {

	private static final Color PARAM_NAME_COLOR = new Color(155, 50, 155);
	private static final Color PARAM_CUSTOM_STORAGE_COLOR =
		OptionsGui.PARAMETER_CUSTOM.getDefaultColor();
	private static final Color PARAM_DYNAMIC_STORAGE_COLOR =
		OptionsGui.PARAMETER_DYNAMIC.getDefaultColor();

	private static final String ELLIPSES = "...";
	public static final int LINE_LENGTH = 80;
	private static final int PARAM_LENGTH_WRAP_THRESHOLD = LINE_LENGTH;

	// shorten the length, since the params may get wrapped and tabbed
	private static final int PARAM_MAX_CHAR_LENGTH = LINE_LENGTH - 20;

	// 13 params + plus the other function signature lines for around 15 lines
	private static final int PARAM_COUNT_THRESHOLD = 13;

	private ToolTipUtils() {
		// utils class--no instance construction
	}

	/**
	 * Examines the give <code>dataType</code> and creates a tool tip for it, 
	 * depending upon its actual class type.
	 * 
	 * <P>Note: the text returned here will be truncated as needed for the type of data.  To
	 * get the full tool tip text, use {@link #getFullToolTipText(DataType)}.
	 * 
	 * @param  dataType The data type from which a tool tip will be 
	 *         created.
	 * @return tool tip text for the given data type.
	 */
	public static String getToolTipText(DataType dataType) {
		return getHTMLRepresentation(dataType).getHTMLString();
	}

	/**
	 * Examines the give <code>dataType</code> and creates a tool tip for it, 
	 * depending upon its actual class type.
	 * 
	 * <P>Note: the text returned here will not be truncated.  This can result in tool tip windows
	 * that are too large to fit in the screen.  For truncated tool tip text, use
	 * {@link #getToolTipText(DataType)}.
	 * 
	 * @param  dataType The data type from which a tool tip will be 
	 *         created.
	 * @return tool tip text for the given data type.
	 */
	public static String getFullToolTipText(DataType dataType) {
		return getHTMLRepresentation(dataType).getFullHTMLString();
	}

	/**
	 * Return dataType details as HTML.
	 * @param dataType the dataType to be represented
	 * @return dataType details formatted as HTML
	 */
	public static HTMLDataTypeRepresentation getHTMLRepresentation(DataType dataType) {
		if (dataType != null) {
			if (dataType instanceof TypeDef) {
				return new TypeDefDataTypeHTMLRepresentation((TypeDef) dataType);
			}
			else if (dataType instanceof Composite) {
				return new CompositeDataTypeHTMLRepresentation((Composite) dataType);
			}
			else if (dataType instanceof Enum) {
				return new EnumDataTypeHTMLRepresentation((Enum) dataType);
			}
			else if (dataType instanceof FunctionDefinition) {
				return new FunctionDataTypeHTMLRepresentation((FunctionDefinition) dataType);
			}
			else if (dataType instanceof Pointer) {
				return new PointerDataTypeHTMLRepresentation((Pointer) dataType);
			}
			else if (dataType instanceof Array) {
				return new ArrayDataTypeHTMLRepresentation((Array) dataType);
			}
			else if (dataType instanceof BitFieldDataType) {
				return new BitFieldDataTypeHTMLRepresentation((BitFieldDataType) dataType);
			}
			else {
				return new DefaultDataTypeHTMLRepresentation(dataType);
			}
		}

		return new NullDataTypeHTMLRepresentation();
	}

	/**
	 * Return an HTML formatted rendering of an external location/function.
	 * 
	 * @param extLoc the location
	 * @param includeSymbolDetails true to include details of the symbol
	 * @return tool tip text for the given external location/function
	 */
	public static String getToolTipText(ExternalLocation extLoc, boolean includeSymbolDetails) {

		if (extLoc.isFunction()) {
			return getToolTipText(extLoc.getFunction(), includeSymbolDetails);
		}

		Symbol s = extLoc.getSymbol();
		StringBuilder buf = new StringBuilder(HTML);

		buf.append("External").append(HTML_SPACE);

		if (includeSymbolDetails) {
			buf.append("Data");
			buf.append(HTML_SPACE).append("-").append(HTML_SPACE);
			buf.append(friendlyEncodeHTML(s.getName(true)));
			Address addr = extLoc.getAddress();
			if (addr != null) {
				buf.append(HTML_SPACE).append("@").append(HTML_SPACE);
				buf.append(addr.toString(true));
			}
			buf.append(BR);
		}

		DataType dt = extLoc.getDataType();
		if (dt == null) {
			dt = DataType.DEFAULT;
		}

		buf.append(colorString(Color.BLACK, friendlyEncodeHTML(dt.getName())));
		buf.append(HTML_SPACE);
		buf.append(friendlyEncodeHTML(s.getName()));

		return buf.toString();
	}

	/**
	 * Return an HTML formatted rendering of a function
	 * 
	 * @param function the function
	 * @param includeSymbolDetails true to include details of the symbol
	 * @return tool tip text for the given function
	 */
	public static String getToolTipText(Function function, boolean includeSymbolDetails) {

		StringBuilder buf = new StringBuilder(HTML);

		ExternalLocation extLoc = function.getExternalLocation();
		if (extLoc != null) {
			buf.append("External").append(HTML_SPACE);
		}
		else if (function.isThunk()) {
			buf.append("Thunk").append(HTML_SPACE);
		}

		if (includeSymbolDetails) {
			buf.append("Function");
			buf.append(HTML_SPACE).append("-").append(HTML_SPACE);
			String functionName = function.getSymbol().getName(true);
			functionName = StringUtilities.trimMiddle(functionName, LINE_LENGTH);
			buf.append(friendlyEncodeHTML(functionName));
			if (extLoc != null) {
				Address addr = extLoc.getAddress();
				if (addr != null) {
					buf.append(HTML_SPACE).append("@").append(HTML_SPACE);
					buf.append(addr.toString(true));
				}
			}
			buf.append(BR);
		}

		buf.append(getFunctionSignaturePreview(function));
		buf.append(BR);

		buf.append("<table cellspacing=0 callpadding=0 border=0>");

		buf.append(generateParameterDetailRow(function.getReturn()));
		for (Parameter p : function.getParameters()) {
			buf.append(generateParameterDetailRow(p));
		}

		if (extLoc != null) {
			String originalImportedName = extLoc.getOriginalImportedName();
			if (originalImportedName != null) {
				buf.append("Imported")
						.append(HTML_SPACE)
						.append("Name:")
						.append(HTML_SPACE)
						.append(friendlyEncodeHTML(originalImportedName));
			}
		}

		buf.append("</table></html>");
		return buf.toString();
	}

	private static String generateParameterDetailRow(Parameter param) {

		String type = param.getDataType().getName();
		String name = param.getName();
		int length = type.length() + 1 + name.length();

		//
		// Bound the max width of the tooltip 
		//
		if (length > PARAM_MAX_CHAR_LENGTH) {
			int half = PARAM_MAX_CHAR_LENGTH / 2;
			int available = half;
			if (type.length() > half) {
				type = type.substring(0, half - 3) + ELLIPSES;
			}
			else {
				available = PARAM_MAX_CHAR_LENGTH - type.length();
			}

			if (name.length() > available) {
				name = name.substring(0, available - 3) + ELLIPSES;
			}
		}

		StringBuilder buf = new StringBuilder();
		buf.append("<tr><td width=10>&nbsp;</td>"); // indent
		buf.append("<td width=\"1%\">");
		buf.append(colorString(Color.BLACK, friendlyEncodeHTML(type)));
		buf.append("</td><td width=\"1%\">");
		Color paramColor =
			param.getFunction().hasCustomVariableStorage() ? PARAM_CUSTOM_STORAGE_COLOR
					: PARAM_DYNAMIC_STORAGE_COLOR;
		buf.append(
			colorString(paramColor, friendlyEncodeHTML(param.getVariableStorage().toString())));
		buf.append("</td><td width=\"1%\">");
		buf.append(colorString(PARAM_NAME_COLOR, friendlyEncodeHTML(name)));

		// consume remaining space and compact other columns
		buf.append("</td><td width=\"100%\">&nbsp;</td></tr>");
		return buf.toString();
	}

	private static String getFunctionSignaturePreview(Function function) {
		/*
		 * The flags (namely 'noreturn'), return type, calling convention, and name are all
		 * streamed directly to the output buffer.
		 * 
		 *  Parameters are encoded into individual strings, and a non-HTML length is tallied
		 *  as each parameter is processed. If the non-HTML length exceeds 
		 *  PARAM_LENGTH_WRAP_THRESHOLD, the parameter strings are streamed into an HTML table
		 *  for pretty-printing; otherwise, they are merged into one string and emitted.  
		 */

		StringBuilder buffy = new StringBuilder();
		if (function.hasNoReturn()) {
			buffy.append("noreturn").append(HTML_SPACE);
		}
		buffy.append(friendlyEncodeHTML(function.getReturnType().getName()));
		buffy.append(HTML_SPACE);
		PrototypeModel callingConvention = function.getCallingConvention();
		if (isNonDefaultCallingConvention(callingConvention)) {
			buffy.append(friendlyEncodeHTML(callingConvention.getName()));
			buffy.append(HTML_SPACE);
		}

		String functionName = StringUtilities.trimMiddle(function.getName(), LINE_LENGTH);
		buffy.append(colorString(Color.BLUE, friendlyEncodeHTML(functionName)));
		buffy.append(HTML_SPACE).append("(");

		buildParameterPreview(function, buffy);

		return buffy.toString();
	}

	private static boolean isNonDefaultCallingConvention(PrototypeModel callingConvention) {
		if (callingConvention == null) {
			return false;
		}

		return !Function.DEFAULT_CALLING_CONVENTION_STRING.equals(callingConvention.getName());
	}

	private static void buildParameterPreview(Function function, StringBuilder buffy) {

		int rawTextLength = 0;
		Parameter[] parameters = function.getParameters();
		List<String> params = new ArrayList<>();
		for (Parameter param : parameters) {
			rawTextLength += generateParameterHtml(param, params);
		}

		if (function.hasVarArgs()) {
			String s = FunctionSignature.VAR_ARGS_DISPLAY_STRING;
			params.add(s);
			rawTextLength += s.length();
		}
		else if (parameters.length == 0) {
			String s = FunctionSignature.VOID_PARAM_DISPLAY_STRING;
			params.add(s);
			rawTextLength += s.length();
		}

		if (rawTextLength > PARAM_LENGTH_WRAP_THRESHOLD) {
			generateParameterTable(buffy, params);
		}
		else {
			// inline parameter string
			buffy.append(StringUtils.join(params, "," + HTML_SPACE));
			buffy.append(')');
		}
	}

	private static void generateParameterTable(StringBuilder buffy, List<String> params) {
		StringBuilder psb = new StringBuilder("<table cellspacing=0 callpadding=0 border=0>");
		for (int i = 0; i < params.size(); i++) {

			String param = params.get(i);

			// The first parameter is appended directly after the declaration
			if (i == 0) {
				buffy.append(param).append(",");
			}
			else {
				psb.append("<tr><td width=75px></td><td>");
				if (i == PARAM_COUNT_THRESHOLD) {
					psb.append(ELLIPSES).append(')');
					i = params.size(); // break
				}
				else {
					psb.append(param).append(i < (params.size() - 1) ? ',' : ')');
				}

				psb.append("</td></tr>");
			}
		}
		buffy.append(psb.toString());
		buffy.append("</table>");
	}

	private static int generateParameterHtml(Parameter param, List<String> params) {
		String type = param.getDataType().getName();
		String name = param.getName();
		int length = type.length() + 1 + name.length();
		int rawTextLength = length;

		//
		// Bound the max width of the tooltip 
		//
		if (length > PARAM_MAX_CHAR_LENGTH) {
			int half = PARAM_MAX_CHAR_LENGTH / 2;
			int available = half;
			if (type.length() > half) {
				type = type.substring(0, half - 3) + ELLIPSES;
			}
			else {
				available = PARAM_MAX_CHAR_LENGTH - type.length();
			}

			if (name.length() > available) {
				name = name.substring(0, available - 3) + ELLIPSES;
			}
		}

		StringBuilder pb = new StringBuilder();
		pb.append(colorString(Color.BLACK, friendlyEncodeHTML(type)));
		pb.append(HTML_SPACE);

		pb.append(colorString(PARAM_NAME_COLOR, friendlyEncodeHTML(name)));
		params.add(pb.toString());
		return rawTextLength;
	}

}
