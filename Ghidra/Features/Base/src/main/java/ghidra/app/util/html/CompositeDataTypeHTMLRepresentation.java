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

import ghidra.app.util.datatype.DataTypeUrl;
import ghidra.app.util.html.diff.*;
import ghidra.program.model.data.*;
import ghidra.util.HTMLUtilities;

public class CompositeDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {

	private static final int MAX_COMPONENT_COUNT = 100;

	protected List<String> warningLines;
	protected List<ValidatableLine> headerContent;
	protected List<ValidatableLine> bodyContent;
	protected TextLine footerText;
	protected TextLine displayName;
	protected List<ValidatableLine> alignmentText;
	protected TextLine alignmentValueText;

	protected static final String ALIGNMENT_VALUE_PREFIX = "Alignment: ";

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

		originalHTMLData = buildHTMLText(warningLines, header, displayName, bodyContent,
			alignmentText, footerText, alignmentValueText);
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

		originalHTMLData = buildHTMLText(warningLines, headerContent, displayName, bodyContent,
			alignmentText, footerText, alignmentValueText);
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
		String alignStr = CompositeDataTypeImpl.getMinAlignmentString(dataType);
		if (alignStr != null && alignStr.length() != 0) {
			list.add(new TextLine(alignStr));
		}
		String packStr = CompositeDataTypeImpl.getPackingString(dataType);
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
		if (comp.isZeroLength()) {
			return list;
		}

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

			list.add(new DataTypeLine(fieldName, type, comment, locatableType, false));
			if (count++ >= MAX_COMPONENT_COUNT) {
				// Prevent a ridiculous number of components from consuming all memory.
				list.add(new DataTypeLine("Warning: Too many components to display...", "", "",
					null, false));
				break;
			}
		}
		if (comp instanceof Structure) {
			Structure struct = (Structure) comp;
			DataTypeComponent flexibleArrayComponent = struct.getFlexibleArrayComponent();
			if (count < MAX_COMPONENT_COUNT && flexibleArrayComponent != null) {
				String fieldName = flexibleArrayComponent.getFieldName();
				String comment = flexibleArrayComponent.getComment();
				DataType dataType = flexibleArrayComponent.getDataType();
				String type = dataType.getDisplayName();
				DataType locatableType = getLocatableDataType(dataType);
				list.add(new DataTypeLine(fieldName, type, comment, locatableType, true));

			}
		}
		return list;
	}

	private static String buildHTMLText(List<String> warningLines,
			List<ValidatableLine> headerLines, TextLine displayName,
			List<ValidatableLine> bodyLines, List<ValidatableLine> alignmentLines,
			TextLine footerLine, TextLine alignmentValueLine) {

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
			TextLine line = (TextLine) iterator.next();
			String headerLine = wrapStringInColor(line.getText(), line.getTextColor());
			buffy.append(headerLine);
		}

		// "<TT> displayName</TT> { "
		String displayNameText = friendlyEncodeHTML(displayName.getText());
		displayNameText = wrapStringInColor(displayNameText, displayName.getTextColor());
		buffy.append(TT_OPEN).append(displayNameText).append(TT_CLOSE).append(HTML_SPACE).append(
			"{").append(HTML_SPACE);

		buffy.append("<TABLE BORDER=0 CELLSPACING=5 CELLPADDING=0>");

		iterator = bodyLines.iterator();
		for (int i = 0; iterator.hasNext(); i++) {
			DataTypeLine line = (DataTypeLine) iterator.next();

			String typeName = generateTypeName(line);
			if (line.isFlexibleArray()) {
				typeName += "[0]";
			}

			String fieldName = friendlyEncodeHTML(line.getName());
			fieldName = wrapStringInColor(fieldName, line.getNameColor());

			int commentLength = MAX_CHARACTER_LENGTH; // give a little extra room for comments
			String typeComment = truncateAsNecessary(line.getComment(), commentLength);
			typeComment = friendlyEncodeHTML(typeComment);
			typeComment = wrapStringInColor(typeComment, line.getCommentColor());

			// start the table row
			buffy.append(TR_OPEN);

			// the name column within the current row
			buffy.append(TD_OPEN).append(TT_OPEN).append(TAB).append(typeName).append(
				TT_CLOSE).append(TD_CLOSE);

			// data type name column
			buffy.append(TD_OPEN).append(HTML_SPACE).append(fieldName).append(TD_CLOSE);

			// data type comment
			buffy.append(TD_OPEN).append(HTML_SPACE).append(typeComment).append(HTML_SPACE).append(
				TD_CLOSE);

			// close the row
			buffy.append(TR_CLOSE);

			if (i > MAX_COMPONENTS) {
// TODO: change to diff color if any of the ellipsed-out args are diffed                
				// if ( cointains unmatching lines ( arguments, i ) )
				// then make the ellipses the diff color                

				buffy.append(TAB).append(ELLIPSES).append(BR);
				break;
			}
		}

		// Alignment
		String alignmentLine = "";
		Iterator<ValidatableLine> alignmentIterator = alignmentLines.iterator();
		for (; alignmentIterator.hasNext();) {
			TextLine line = (TextLine) alignmentIterator.next();
			alignmentLine += HTML_SPACE + wrapStringInColor(line.getText(), line.getTextColor());
		}

		// close the table, the structure and then the HTML
		buffy.append(TABLE_CLOSE).append("}").append(TT_OPEN).append(alignmentLine).append(
			TT_CLOSE).append(BR);

		addAlignmentValue(alignmentValueLine.getText(), buffy);
		addDataTypeLength(footerLine.getText(), buffy);

		buffy.append(BR);

		return buffy.toString();
	}

	private static String generateTypeName(DataTypeLine line) {

		String type = truncateAsNecessary(line.getType());
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
