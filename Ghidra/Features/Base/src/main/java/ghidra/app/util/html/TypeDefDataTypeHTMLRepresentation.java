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

import java.util.*;

import org.apache.commons.lang3.StringUtils;

import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.app.util.ToolTipUtils;
import ghidra.app.util.html.diff.DataTypeDiff;
import ghidra.app.util.html.diff.DataTypeDiffBuilder;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.data.*;
import ghidra.util.HTMLUtilities;

public class TypeDefDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {

	private final TypeDef typeDef;

	private List<String> warningLines;
	protected List<ValidatableLine> headerContent;
	protected List<ValidatableLine> bodyContent;

	private String truncatedHtmlData;

	// private constructor for making diff copies
	private TypeDefDataTypeHTMLRepresentation(TypeDef typeDef, List<String> warningLines,
			List<ValidatableLine> headerLines, List<ValidatableLine> bodyLines) {
		this.typeDef = typeDef;
		this.warningLines = warningLines;
		this.headerContent = headerLines;
		this.bodyContent = bodyLines;

		List<ValidatableLine> trimmedHeaderContent = buildHeaderText(true);
		List<ValidatableLine> trimmedBodyContent = buildBodyText(getBaseDataType(), true);
		truncatedHtmlData =
			buildHTMLText(typeDef, warningLines, trimmedHeaderContent, trimmedBodyContent, true);
	}

	public TypeDefDataTypeHTMLRepresentation(TypeDef typeDef) {
		this.typeDef = typeDef;

		warningLines = buildWarnings();
		headerContent = buildHeaderText(false);
		bodyContent = buildBodyText(getBaseDataType(), false);

		originalHTMLData = buildHTMLText(typeDef, warningLines, headerContent, bodyContent, false);

		List<ValidatableLine> trimmedHeaderContent = buildHeaderText(true);
		List<ValidatableLine> trimmedBodyContent = buildBodyText(getBaseDataType(), true);
		truncatedHtmlData =
			buildHTMLText(typeDef, warningLines, trimmedHeaderContent, trimmedBodyContent, true);
	}

	private DataType getBaseDataType() {
		DataType baseDataType = typeDef;
		while (!(baseDataType instanceof BuiltInDataType) && (baseDataType instanceof TypeDef)) {
			TypeDef td = (TypeDef) baseDataType;
			baseDataType = getBasePointerArrayDataType(td.getDataType());
		}
		return baseDataType;
	}

	private static DataType getBasePointerArrayDataType(DataType dt) {
		while ((dt instanceof Pointer) || (dt instanceof Array)) {
			if (dt instanceof Pointer) {
				dt = ((Pointer) dt).getDataType();
			}
			else {
				dt = ((Array) dt).getDataType();
			}
		}
		return dt;
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

	protected List<String> buildWarnings() {
		DataType baseType = typeDef.getBaseDataType();
		if (!(baseType instanceof Composite) || !baseType.isZeroLength()) {
			return Collections.emptyList();
		}
		List<String> list = new ArrayList<>();
		list.add(
			"WARNING! Refers to Empty " + (baseType instanceof Structure ? "Structure" : "Union"));
		return list;
	}

	@Override
	protected TextLine buildFooterText(DataType dataType) {
		if (dataType.isZeroLength()) {
			return new TextLine("0");
		}
		return super.buildFooterText(dataType);
	}

	private String getDataTypeNameHTML(TypeDef td, boolean trim) {
		String name = td.getName();
		if (trim) {
			name = truncateAsNecessary(name);
		}
		name = HTMLUtilities.friendlyEncodeHTML(name);

		StringBuilder buffy = new StringBuilder(TT_OPEN);
		if (td.isAutoNamed()) {
			buffy.append("auto-typedef ");
			buffy.append(name);
		}
		else {
			buffy.append("typedef ");
			buffy.append(td != typeDef ? generateTypeName(td, null, trim) : name);
			buffy.append(" ");
			buffy.append(generateTypeName(td.getDataType(), null, trim));
		}
		buffy.append(TT_CLOSE).append(BR);
		return buffy.toString();
	}

	protected List<ValidatableLine> buildHeaderText(boolean trim) {

		DataType baseDataType = typeDef.getDataType();

		List<ValidatableLine> lines = new ArrayList<>();
		lines.add(new TextLine(getDataTypeNameHTML(typeDef, trim)));

		if (!typeDef.isAutoNamed()) {
			// Show modified default settings details (i.e., TypeDefSettingsDefinition)
			StringBuilder buffy = new StringBuilder();
			Settings defaultSettings = typeDef.getDefaultSettings();
			for (SettingsDefinition settingsDef : typeDef.getSettingsDefinitions()) {
				if (!(settingsDef instanceof TypeDefSettingsDefinition) ||
					!settingsDef.hasValue(defaultSettings)) {
					continue;
				}
				if (buffy.length() == 0) {
					buffy.append(INDENT_OPEN);
				}
				else {
					buffy.append(BR);
				}
				buffy.append(TT_OPEN)
						.append(settingsDef.getName())
						.append(": ")
						.append(settingsDef.getValueString(defaultSettings));
				buffy.append(TT_CLOSE);
			}
			if (buffy.length() != 0) {
				buffy.append(INDENT_CLOSE);
				lines.add(new TextLine(buffy.toString()));
			}
		}

		baseDataType = typeDef.getBaseDataType();
		if (baseDataType instanceof Pointer || baseDataType instanceof Array) {
			String lengthAndAlignmentStr =
				addDataTypeLengthAndAlignment(typeDef, new StringBuilder()).toString();
			lines.add(new TextLine(INDENT_OPEN + lengthAndAlignmentStr + INDENT_CLOSE));
		}

		baseDataType = getBasePointerArrayDataType(baseDataType);
		boolean firstBaseTypedef = true;
		while (baseDataType instanceof TypeDef) {
			TypeDef td = (TypeDef) baseDataType;
			if (!td.isAutoNamed()) {
				String br = "";
				if (firstBaseTypedef) {
					br = "<BR>";
					firstBaseTypedef = false;
				}
				lines.add(new TextLine(br + getDataTypeNameHTML(td, trim)));
			}
			baseDataType = getBasePointerArrayDataType(td.getDataType());
		}

		return lines;
	}

	private List<ValidatableLine> buildBodyText(DataType baseDataType, boolean trim) {
		List<ValidatableLine> lines = new ArrayList<>();
		if (baseDataType instanceof BuiltInDataType) {
			buildHTMLTextForBuiltIn(lines, baseDataType);
		}
		else if (baseDataType != null) {
			buildHTMLTextForBaseDataType(lines, baseDataType, trim);
		}
		return lines;
	}

	private static String buildHTMLText(TypeDef typeDef, List<String> warningLines,
			List<ValidatableLine> headerLines, List<ValidatableLine> bodyLines, boolean trim) {

		StringBuilder buffy = new StringBuilder();

		// warnings
		Iterator<String> warnings = warningLines.iterator();
		for (; warnings.hasNext();) {
			String warning = warnings.next();
			String warningLine = wrapStringInColor(warning, Messages.ERROR);
			buffy.append(warningLine).append(BR);
		}

		// header
		Iterator<ValidatableLine> iterator = headerLines.iterator();
		for (; iterator.hasNext();) {
			TextLine line = (TextLine) iterator.next(); // This text should already be encoded.
			String headerLine = line.getText();
			if (trim) {
				headerLine = truncateAsNecessary(headerLine, ToolTipUtils.LINE_LENGTH);
			}
			headerLine = wrapStringInColor(line.getText(), line.getTextColor());
			buffy.append(headerLine);
		}

		// body
		buffy.append(BR);

		iterator = bodyLines.iterator();
		for (; iterator.hasNext();) {

			// This text should already be encoded and already trimmed
			TextLine line = (TextLine) iterator.next();
			String bodyLine = line.getText();
			bodyLine = wrapStringInColor(line.getText(), line.getTextColor());
			buffy.append(bodyLine);
		}

		return buffy.toString();
	}

	private static void buildHTMLTextForBuiltIn(List<ValidatableLine> lines,
			DataType baseDataType) {
		lines.add(new TextLine(TT_OPEN));
		String encodedName =
			HTMLUtilities.friendlyEncodeHTML(baseDataType.getDisplayName());
		lines.add(new TextLine(encodedName));
		lines.add(new TextLine(TT_CLOSE));
		lines.add(new TextLine(BR));
		lines.add(new TextLine(INDENT_OPEN));

		String description = baseDataType.getDescription();
		if (!StringUtils.isBlank(description)) {
			String encodedDescription =
				HTMLUtilities.friendlyEncodeHTML(description);
			lines.add(new TextLine(encodedDescription));
			lines.add(new TextLine(BR));
		}

		lines.add(new TextLine(
			addDataTypeLengthAndAlignment(baseDataType, new StringBuilder()).toString()));
		lines.add(new TextLine(INDENT_CLOSE));
	}

	private static void buildHTMLTextForBaseDataType(List<ValidatableLine> lines,
			DataType baseDataType, boolean trim) {

		HTMLDataTypeRepresentation baseRepresentation =
			ToolTipUtils.getHTMLRepresentation(baseDataType);

		String baseHTML = baseRepresentation.getFullHTMLContentString();
		if (trim) {
			baseHTML = baseRepresentation.getHTMLContentString();
		}

		lines.add(new TextLine(baseHTML));

		if (baseHTML.indexOf(LENGTH_PREFIX) < 0 && baseDataType.getLength() >= 0) {
			StringBuilder buffy = new StringBuilder();
			addDataTypeLengthAndAlignment(baseDataType, buffy);
			lines.add(new TextLine(buffy.toString()));
		}
	}

	@Override
	public HTMLDataTypeRepresentation[] diff(HTMLDataTypeRepresentation otherRepresentation) {
		if (this == otherRepresentation) {
			return new HTMLDataTypeRepresentation[] { this, this };
		}

		if (!(otherRepresentation instanceof TypeDefDataTypeHTMLRepresentation)) {
			return completelyDifferentDiff(otherRepresentation);
		}

		TypeDefDataTypeHTMLRepresentation typeDefRepresentation =
			(TypeDefDataTypeHTMLRepresentation) otherRepresentation;
		DataType myBaseDataType = getBaseDataType();
		DataType otherBaseDataType = typeDefRepresentation.getBaseDataType();

		HTMLDataTypeRepresentation myBaseRepresentation =
			ToolTipUtils.getHTMLRepresentation(myBaseDataType);
		HTMLDataTypeRepresentation otherBaseRepresentation =
			ToolTipUtils.getHTMLRepresentation(otherBaseDataType);
		HTMLDataTypeRepresentation[] diffs = doDiff(myBaseRepresentation, otherBaseRepresentation);

		List<ValidatableLine> header = new ArrayList<>(headerContent);
		List<ValidatableLine> body = new ArrayList<>();

		if (diffs != null) {
			body.add(new TextLine(diffs[0].getFullHTMLContentString()));
		}

		List<ValidatableLine> otherHeader = new ArrayList<>(typeDefRepresentation.headerContent);
		List<ValidatableLine> otherBody = new ArrayList<>();

		if (diffs != null) {
			otherBody.add(new TextLine(diffs[1].getFullHTMLContentString()));
		}

		DataTypeDiff headerDiff =
			DataTypeDiffBuilder.diffHeader(getDiffInput(header), getDiffInput(otherHeader));

		List<String> noWarnings = Collections.emptyList();

		return new HTMLDataTypeRepresentation[] {
			new TypeDefDataTypeHTMLRepresentation(typeDef, noWarnings, headerDiff.getLeftLines(),
				body),
			new TypeDefDataTypeHTMLRepresentation(typeDefRepresentation.typeDef, noWarnings,
				headerDiff.getRightLines(), otherBody) };
	}

	private HTMLDataTypeRepresentation[] doDiff(HTMLDataTypeRepresentation myBaseRepresentation,
			HTMLDataTypeRepresentation otherBaseRepresentation) {

		HTMLDataTypeRepresentation[] diffs = myBaseRepresentation.diff(otherBaseRepresentation);
		return diffs;
	}

}
