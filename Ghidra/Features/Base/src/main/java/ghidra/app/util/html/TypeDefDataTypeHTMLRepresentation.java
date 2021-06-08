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

import java.awt.Color;
import java.util.*;

import ghidra.app.util.ToolTipUtils;
import ghidra.app.util.html.diff.DataTypeDiff;
import ghidra.app.util.html.diff.DataTypeDiffBuilder;
import ghidra.program.model.data.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.StringUtilities;

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

		List<ValidatableLine> trimmedHeaderContent = buildHeaderText(typeDef, true);
		List<ValidatableLine> trimmedBodyContent = buildBodyText(getBaseDataType(), true);
		truncatedHtmlData =
			buildHTMLText(typeDef, warningLines, trimmedHeaderContent, trimmedBodyContent, true);
	}

	public TypeDefDataTypeHTMLRepresentation(TypeDef typeDef) {
		this.typeDef = typeDef;

		warningLines = buildWarnings();
		headerContent = buildHeaderText(typeDef, false);
		bodyContent = buildBodyText(getBaseDataType(), false);

		originalHTMLData = buildHTMLText(typeDef, warningLines, headerContent, bodyContent, false);

		List<ValidatableLine> trimmedHeaderContent = buildHeaderText(typeDef, true);
		List<ValidatableLine> trimmedBodyContent = buildBodyText(getBaseDataType(), true);
		truncatedHtmlData =
			buildHTMLText(typeDef, warningLines, trimmedHeaderContent, trimmedBodyContent, true);
	}

	protected DataType getBaseDataType() {
		return getBaseDataType(typeDef);
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

	private static DataType getBaseDataType(DataType dataType) {
		DataType basedataType = dataType;
		while (basedataType instanceof TypeDef) {
			basedataType = ((TypeDef) basedataType).getDataType();
			while (basedataType instanceof Pointer) {
				basedataType = ((Pointer) basedataType).getDataType();
			}
		}
		return basedataType;
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

	protected List<ValidatableLine> buildHeaderText(DataType dataType, boolean trim) {
		DataType baseDataType = typeDef;
		List<ValidatableLine> lines = new ArrayList<>();
		while (baseDataType instanceof TypeDef) {
			StringBuilder buffy = new StringBuilder();
			String baseDtString = baseDataType.toString();
			if (trim) {
				baseDtString = StringUtilities.trimMiddle(baseDtString, ToolTipUtils.LINE_LENGTH);
			}
			String encodedBaseDt = HTMLUtilities.friendlyEncodeHTML(baseDtString);
			buffy.append(TT_OPEN).append(encodedBaseDt).append(TT_CLOSE).append(BR);
			lines.add(new TextLine(buffy.toString()));
			baseDataType = ((TypeDef) baseDataType).getDataType();
			while (baseDataType instanceof Pointer) {
				baseDataType = ((Pointer) baseDataType).getDataType();
			}
		}
		return lines;
	}

	private List<ValidatableLine> buildBodyText(DataType baseDataType, boolean trim) {
		List<ValidatableLine> lines = new ArrayList<>();
		if (baseDataType instanceof BuiltInDataType) {
			buildHTMLTextForBuiltIn(lines, baseDataType);
		}
		else {
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
			String warningLine = wrapStringInColor(warning, Color.RED);
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
		buffy.append("TypeDef Base Data Type: ").append(BR);

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
			DataType basedataType) {
		lines.add(new TextLine(INDENT_OPEN));
		lines.add(new TextLine(TT_OPEN));
		String dataTypeDescriptionOrName = getDataTypeDescriptionOrName(basedataType);
		String encodedDescriptionOrName =
			HTMLUtilities.friendlyEncodeHTML(dataTypeDescriptionOrName);
		lines.add(new TextLine(encodedDescriptionOrName));
		lines.add(new TextLine(TT_CLOSE));
		StringBuilder buffy = addDataTypeLength(basedataType, new StringBuilder());
		lines.add(new TextLine(buffy.toString()));
		lines.add(new TextLine(INDENT_CLOSE));
	}

	private static String getDataTypeDescriptionOrName(DataType dataType) {
		String description = dataType.getDescription();
		if (description == null || description.length() == 0) {
			return dataType.getName();
		}
		return description;
	}

	private static void buildHTMLTextForBaseDataType(List<ValidatableLine> lines,
			DataType basedataType, boolean trim) {
		lines.add(new TextLine(INDENT_OPEN));

		HTMLDataTypeRepresentation baseRepresentation =
			ToolTipUtils.getHTMLRepresentation(basedataType);

		String baseHTML = baseRepresentation.getFullHTMLContentString();
		if (trim) {
			baseHTML = baseRepresentation.getHTMLContentString();
		}

		lines.add(new TextLine(baseHTML));

		if (baseHTML.indexOf(LENGTH_PREFIX) < 0) {
			StringBuilder buffy = addDataTypeLength(basedataType, new StringBuilder());
			lines.add(new TextLine(buffy.toString()));
		}

		lines.add(new TextLine(INDENT_CLOSE));
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
