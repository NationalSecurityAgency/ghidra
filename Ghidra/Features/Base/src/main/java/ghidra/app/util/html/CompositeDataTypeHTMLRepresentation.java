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

import static ghidra.util.HTMLUtilities.*;

import java.awt.Color;
import java.util.*;

import ghidra.app.util.ToolTipUtils;
import ghidra.app.util.datatype.DataTypeUrl;
import ghidra.app.util.html.diff.*;
import ghidra.program.model.data.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.StringUtilities;

public class CompositeDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {

	private static final int MAX_COMPONENT_COUNT = 1000;
	private static final int MAX_LINE_COUNT = 15;

	protected List<String> warningLines;
	protected List<ValidatableLine> headerContent;
	protected List<ValidatableLine> bodyContent;
	protected TextLine footerText;
	protected TextLine displayName;
	protected List<ValidatableLine> alignmentText;
	protected TextLine alignmentValueText;

	protected static final String ALIGNMENT_VALUE_PREFIX = "Alignment: ";

	private String truncatedHtmlData;

	// private constructor for making diff copies
	protected CompositeDataTypeHTMLRepresentation(List<String> warningLines,
			List<ValidatableLine> header, List<ValidatableLine> bodyContent,
			List<ValidatableLine> alignmentText, TextLine footerText, TextLine displayName,
			TextLine alignmentValue) {
		this.warningLines = warningLines;
		this.headerContent = header;
		this.bodyContent = bodyContent;
		this.footerText = footerText;
		this.displayName = displayName;
		this.alignmentText = alignmentText;
		this.alignmentValueText = alignmentValue;

		originalHTMLData = buildHTMLText(false);
		truncatedHtmlData = buildHTMLText(true);
	}

	public CompositeDataTypeHTMLRepresentation(Composite comp) {
		warningLines = buildWarnings(comp);
		headerContent = buildHeaderText(comp);
		bodyContent = buildContent(comp);
		alignmentText = buildAlignmentText(comp);
		footerText = buildFooterText(comp);
		String type = "";
		if (comp instanceof Union) {
			type = "union ";
		}
		else if (comp instanceof Structure) {
			type = "struct ";
		}
		displayName = new TextLine(type + comp.getDisplayName() + " ");
		alignmentValueText = buildAlignmentValueText(comp);

		originalHTMLData = buildHTMLText(false);
		truncatedHtmlData = buildHTMLText(true);
	}

	protected List<String> buildWarnings(Composite comp) {
		if (!comp.isZeroLength()) {
			return Collections.emptyList();
		}
		List<String> list = new ArrayList<>();
		list.add("WARNING! Empty " + (comp instanceof Structure ? "Structure" : "Union"));
		return list;
	}

	@Override
	protected TextLine buildFooterText(DataType dataType) {
		if (dataType.isZeroLength()) {
			return new TextLine("0");
		}
		return super.buildFooterText(dataType);
	}

	protected List<ValidatableLine> buildAlignmentText(Composite dataType) {
		List<ValidatableLine> list = new ArrayList<>();
		String alignStr = CompositeInternal.getMinAlignmentString(dataType);
		if (alignStr != null && alignStr.length() != 0) {
			list.add(new TextLine(alignStr));
		}
		String packStr = CompositeInternal.getPackingString(dataType);
		if (packStr != null && packStr.length() != 0) {
			list.add(new TextLine(packStr));
		}
		return list;
	}

	protected TextLine buildAlignmentValueText(Composite composite) {
		return new TextLine("" + composite.getAlignment());
	}

	private List<ValidatableLine> buildContent(Composite comp) {
		List<ValidatableLine> list = new ArrayList<>();
		int count = 0;
		DataTypeComponent[] components = comp.getComponents();
		for (DataTypeComponent dataTypeComponent : components) {
			String fieldName = dataTypeComponent.getFieldName();
			String comment = dataTypeComponent.getComment();

			DataType dataType = dataTypeComponent.getDataType();
			String type = "<unknown type>";
			DataType locatableType = null;
			if (dataType != null) {
				type = dataType.getDisplayName();
				locatableType = getLocatableDataType(dataType);
			}

			list.add(new DataTypeLine(fieldName, type, comment, locatableType));
			if (count++ >= MAX_COMPONENT_COUNT) {
				// Prevent a ridiculous number of components from consuming all memory.
				list.add(
					new DataTypeLine("", "Warning: Too many components to display...", "", null));
				break;
			}
		}
		return list;
	}

	/**
	 * Full html is not limited by the number of lines to display; the truncated html line
	 * count is limited.  Truncated data will only be returned when the text is being trimmed.
	 * @param trim true signals to truncate lines that are too long and to cap the maximum number
	 *        of lines that can be displayed
	 * @return the text
	 */
	private String buildHTMLText(boolean trim) {

		StringBuilder fullHtml = new StringBuilder();
		StringBuilder truncatedHtml = new StringBuilder();
		int lineCount = 0;

		// warnings
		Iterator<String> warnings = warningLines.iterator();
		for (; warnings.hasNext();) {
			String warning = warnings.next();
			String warningLine = wrapStringInColor(warning, Color.RED);

			//@formatter:off
			append(fullHtml, truncatedHtml, lineCount, warningLine, 
                                                       BR,
                                                       BR);
			//@formatter:on
			lineCount++;
		}

		//@formatter:off
		append(fullHtml, truncatedHtml, lineCount, ALIGNMENT_VALUE_PREFIX,
												   alignmentValueText.getText(), 
												   BR);
		append(fullHtml, truncatedHtml, lineCount, LENGTH_PREFIX,
												   footerText.getText(), 
												   BR);
		append(fullHtml, truncatedHtml, lineCount, BR, BR);
		//@formatter:on

		// header
		Iterator<ValidatableLine> iterator = headerContent.iterator();
		for (; iterator.hasNext();) {
			TextLine line = (TextLine) iterator.next();
			String text = line.getText();
			if (trim) {
				text = truncateAsNecessary(text);
			}
			String headerLine = wrapStringInColor(text, line.getTextColor());
			append(fullHtml, truncatedHtml, lineCount, headerLine);
			lineCount++;
		}

		// "<TT> displayName</TT> { "
		String name = displayName.getText();
		if (trim) {
			name = StringUtilities.trimMiddle(name, ToolTipUtils.LINE_LENGTH);
		}
		String displayNameText = friendlyEncodeHTML(name);
		displayNameText = wrapStringInColor(displayNameText, displayName.getTextColor());

		//@formatter:off
		append(fullHtml, truncatedHtml, lineCount, TT_OPEN, 
                                                   displayNameText,
                                                   TT_CLOSE,
                                                   HTML_SPACE,
                                                   "{",
                                                   HTML_SPACE);
		//@formatter:on
		lineCount++;

		String tableOpen = "<TABLE BORDER=0 CELLSPACING=5 CELLPADDING=0>";
		fullHtml.append(tableOpen);
		truncatedHtml.append(tableOpen);

		iterator = bodyContent.iterator();
		for (; iterator.hasNext(); lineCount++) {

			iterator.hasNext();

			StringBuilder lineBuffer = new StringBuilder();
			DataTypeLine line = (DataTypeLine) iterator.next();
			String typeName = generateTypeName(line, trim);

			int fieldLength = ToolTipUtils.LINE_LENGTH / 2;
			String fieldName = line.getName();
			if (trim) {
				fieldName = StringUtilities.trimMiddle(fieldName, fieldLength);
			}
			fieldName = friendlyEncodeHTML(fieldName);
			fieldName = wrapStringInColor(fieldName, line.getNameColor());

			String typeComment = line.getComment();
			if (trim) {
				typeComment = truncateAsNecessary(typeComment, fieldLength);
			}
			typeComment = friendlyEncodeHTML(typeComment);
			typeComment = wrapStringInColor(typeComment, line.getCommentColor());

			// start the table row
			lineBuffer.append(TR_OPEN);

			// the name column within the current row
			lineBuffer.append(TD_OPEN)
					.append(TT_OPEN)
					.append(TAB)
					.append(typeName)
					.append(
						TT_CLOSE)
					.append(TD_CLOSE);

			// data type name column
			lineBuffer.append(TD_OPEN).append(HTML_SPACE).append(fieldName).append(TD_CLOSE);

			// data type comment
			lineBuffer.append(TD_OPEN)
					.append(HTML_SPACE)
					.append(typeComment)
					.append(HTML_SPACE)
					.append(
						TD_CLOSE);

			// close the row
			lineBuffer.append(TR_CLOSE);

			String lineString = lineBuffer.toString();
			append(fullHtml, truncatedHtml, lineCount, lineString);
		}

		// show ellipses if needed; the truncated html is much shorter than the full html
		if (lineCount >= MAX_LINE_COUNT) {
			truncatedHtml.append(TAB).append(ELLIPSES).append(BR);
		}

		// Alignment
		String alignmentLine = "";
		Iterator<ValidatableLine> alignmentIterator = alignmentText.iterator();
		for (; alignmentIterator.hasNext();) {
			TextLine line = (TextLine) alignmentIterator.next();
			alignmentLine += HTML_SPACE + wrapStringInColor(line.getText(), line.getTextColor());
		}

		// close the table, the structure and then the HTML
		StringBuilder trailingLines = new StringBuilder();
		trailingLines.append(TABLE_CLOSE)
				.append("}")
				.append(TT_OPEN)
				.append(alignmentLine)
				.append(
					TT_CLOSE)
				.append(BR);

		String trailingString = trailingLines.toString();
		fullHtml.append(trailingString);
		truncatedHtml.append(trailingString);

		if (trim) {
			return truncatedHtml.toString();
		}
		return fullHtml.toString();
	}

	private static void append(StringBuilder fullHtml, StringBuilder truncatedHtml,
			int lineCount, String... content) {

		for (String string : content) {
			fullHtml.append(string);
		}

		maybeAppend(truncatedHtml, lineCount, content);
	}

	private static void maybeAppend(StringBuilder buffer, int lineCount, String... content) {
		if (lineCount > MAX_LINE_COUNT) {
			return;
		}

		for (String string : content) {
			buffer.append(string);
		}
	}

	private static String generateTypeName(DataTypeLine line, boolean trim) {

		String type = line.getType();
		if (true) {
			type = truncateAsNecessary(line.getType());
		}
		type = friendlyEncodeHTML(type);
		type = wrapStringInColor(type, line.getTypeColor());

		if (!line.hasUniversalId()) {
			return type;
		}

		//
		// Markup the name with info for later hyperlink capability, as needed by the client
		//
		DataType dt = line.getDataType();
		DataTypeUrl url = new DataTypeUrl(dt);
		String wrapped = HTMLUtilities.wrapWithLinkPlaceholder(type, url.toString());
		return wrapped;
	}

	protected static StringBuilder addAlignmentValue(String alignmentValueString,
			StringBuilder buffer) {

		buffer.append(BR);
		buffer.append(ALIGNMENT_VALUE_PREFIX + alignmentValueString);

		return buffer;
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
		return new EmptyDataTypeLine();
	}

	@Override
	public HTMLDataTypeRepresentation[] diff(HTMLDataTypeRepresentation otherRepresentation) {
		if (this == otherRepresentation) {
			return new HTMLDataTypeRepresentation[] { this, this };
		}

		if (!(otherRepresentation instanceof CompositeDataTypeHTMLRepresentation)) {
			// completely different, make it as such
			return completelyDifferentDiff(otherRepresentation);
		}

		CompositeDataTypeHTMLRepresentation compositeRepresentation =
			(CompositeDataTypeHTMLRepresentation) otherRepresentation;

		List<ValidatableLine> header = copyLines(headerContent);
		List<ValidatableLine> body = copyLines(bodyContent);
		TextLine name = new TextLine(displayName.getText());
		List<ValidatableLine> alignment = copyLines(alignmentText);

		List<ValidatableLine> otherHeader = copyLines(compositeRepresentation.headerContent);
		List<ValidatableLine> otherBody = copyLines(compositeRepresentation.bodyContent);
		TextLine otherName = new TextLine(compositeRepresentation.displayName.getText());
		List<ValidatableLine> otherAlignment = copyLines(compositeRepresentation.alignmentText);

		DataTypeDiff headerDiff =
			DataTypeDiffBuilder.diffHeader(getDiffInput(header), getDiffInput(otherHeader));

		DataTypeDiff bodyDiff =
			DataTypeDiffBuilder.diffBody(getDiffInput(body), getDiffInput(otherBody));

		diffTextLine(name, otherName);
		diffAlignment(alignment, otherAlignment);

		List<String> noWarnings = Collections.emptyList();

		return new HTMLDataTypeRepresentation[] {
			new CompositeDataTypeHTMLRepresentation(noWarnings, headerDiff.getLeftLines(),
				bodyDiff.getLeftLines(), alignment, footerText, name, alignmentValueText),
			new CompositeDataTypeHTMLRepresentation(noWarnings, headerDiff.getRightLines(),
				bodyDiff.getRightLines(), otherAlignment, compositeRepresentation.footerText,
				otherName, compositeRepresentation.alignmentValueText), };
	}

	protected void diffAlignment(List<ValidatableLine> myLines, List<ValidatableLine> otherLines) {

		HTMLDataTypeRepresentationDiffInput myInput = getDiffInput(myLines);
		HTMLDataTypeRepresentationDiffInput otherInput = getDiffInput(otherLines);

		DiffLines mine = new DiffLines(myInput);
		DiffLines other = new DiffLines(otherInput);

		DataTypeDiffBuilder.padLines(mine, other);

		DataTypeDiffBuilder.highlightDifferences(mine, other);
	}

}
