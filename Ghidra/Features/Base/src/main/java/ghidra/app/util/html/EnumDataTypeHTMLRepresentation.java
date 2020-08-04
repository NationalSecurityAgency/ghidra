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

import ghidra.app.util.html.diff.DataTypeDiff;
import ghidra.app.util.html.diff.DataTypeDiffBuilder;
import ghidra.program.model.data.Enum;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.AssertException;

public class EnumDataTypeHTMLRepresentation extends HTMLDataTypeRepresentation {

	protected List<ValidatableLine> headerContent;
	protected List<ValidatableLine> bodyContent;
	protected TextLine footerLine;
	protected TextLine displayName;

	// private constructor for making diff copies
	private EnumDataTypeHTMLRepresentation(List<ValidatableLine> headerLines, TextLine displayName,
			List<ValidatableLine> bodyContent, TextLine footerLine) {
		this.headerContent = headerLines;
		this.displayName = displayName;
		this.bodyContent = bodyContent;
		this.footerLine = footerLine;
		originalHTMLData = buildHTMLText(headerLines, displayName, bodyContent, footerLine);
	}

	public EnumDataTypeHTMLRepresentation(Enum enumDataType) {
		headerContent = buildHeaderText(enumDataType);
		bodyContent = buildContent(enumDataType);
		footerLine = buildFooterText(enumDataType);
		displayName = new TextLine(enumDataType.getDisplayName());
		originalHTMLData = buildHTMLText(headerContent, displayName, bodyContent, footerLine);
	}

	@Override
	protected PlaceHolderLine createPlaceHolderLine(ValidatableLine oppositeLine) {
		if (!(oppositeLine instanceof TextLine)) {
			throw new AssertException("I didn't know you could pass me other types of lines?!");
		}
		TextLine textLine = (TextLine) oppositeLine;
		int stringLength = textLine.getText().length();
		return new EmptyTextLine(stringLength);
	}

	private List<ValidatableLine> buildContent(Enum enumDataType) {
		long[] values = enumDataType.getValues();
		Arrays.sort(values);

		int n = enumDataType.getLength();
		List<ValidatableLine> list = new ArrayList<>(values.length);
		for (long value : values) {
			String name = enumDataType.getName(value);

			String hexString = Long.toHexString(value);
			if (value < 0) {
				// Long will print leading FF for 8 bytes, regardless of enum size.  Keep only
				// n bytes worth of text.  For example, when n is 2, turn FFFFFFFFFFFFFF12 into FF12
				int length = hexString.length();
				hexString = hexString.substring(length - (n * 2));
			}
			list.add(new TextLine(name + " = 0x" + hexString));
		}

		return list;
	}

	private static String buildHTMLText(List<ValidatableLine> headerLines, TextLine displayName,
			List<ValidatableLine> bodyLines, TextLine footerLine) {

		StringBuilder buffy = new StringBuilder();

		// header
		Iterator<ValidatableLine> iterator = headerLines.iterator();
		for (; iterator.hasNext();) {
			TextLine line = (TextLine) iterator.next();
			String encodedHeaderLine = line.getText();
			String headerLine = wrapStringInColor(encodedHeaderLine, line.getTextColor());
			buffy.append(headerLine);
		}

		// "<TT> displayName { "
		String encodedDisplayName = HTMLUtilities.friendlyEncodeHTML(displayName.getText());
		String displayNameText = wrapStringInColor(encodedDisplayName, displayName.getTextColor());
		buffy.append(TT_OPEN)
				.append(displayNameText)
				.append(TT_CLOSE)
				.append(HTML_SPACE)
				.append(
					"{")
				.append(HTML_SPACE)
				.append(BR);

		int length = bodyLines.size();
		for (int i = 0; i < length; i++) {
			TextLine textLine = (TextLine) bodyLines.get(i);
			String text = textLine.getText();
			String encodedBodyLine = HTMLUtilities.friendlyEncodeHTML(text);
			text = wrapStringInColor(encodedBodyLine, textLine.getTextColor());

			buffy.append(TAB).append(text).append(HTML_SPACE);
			if (i < length - 1) {
				buffy.append(BR);
			}
			if (i > MAX_COMPONENTS) {
// TODO: change to diff color if any of the ellipsed-out args are diffed                
				// if ( cointains unmatching lines ( arguments, i ) )
				// then make the ellipses the diff color                
				buffy.append(TAB).append(ELLIPSES).append(BR);
				break;
			}
		}

		buffy.append(BR).append("}").append(BR).append(TT_CLOSE);

		addDataTypeLength(footerLine.getText(), buffy);

		return buffy.toString();
	}

	@Override
	public HTMLDataTypeRepresentation[] diff(HTMLDataTypeRepresentation otherRepresentation) {
		if (this == otherRepresentation) {
			return new HTMLDataTypeRepresentation[] { this, this };
		}

		if (!(otherRepresentation instanceof EnumDataTypeHTMLRepresentation)) {
			// completely different, make it as such
			return completelyDifferentDiff(otherRepresentation);
		}

		EnumDataTypeHTMLRepresentation compositeRepresentation =
			(EnumDataTypeHTMLRepresentation) otherRepresentation;

		List<ValidatableLine> header = copyLines(headerContent);
		List<ValidatableLine> body = copyLines(bodyContent);
		TextLine diffDisplayName = new TextLine(displayName.getText());

		List<ValidatableLine> otherHeader = copyLines(compositeRepresentation.headerContent);
		List<ValidatableLine> otherBody = copyLines(compositeRepresentation.bodyContent);
		TextLine otherDiffDisplayName = new TextLine(compositeRepresentation.displayName.getText());

		DataTypeDiff headerDiff =
			DataTypeDiffBuilder.diffHeader(getDiffInput(header), getDiffInput(otherHeader));

		DataTypeDiff bodyDiff =
			DataTypeDiffBuilder.diffBody(getDiffInput(body), getDiffInput(otherBody));

		diffTextLine(diffDisplayName, otherDiffDisplayName);

		return new HTMLDataTypeRepresentation[] {
			new EnumDataTypeHTMLRepresentation(headerDiff.getLeftLines(), diffDisplayName,
				bodyDiff.getLeftLines(), footerLine),
			new EnumDataTypeHTMLRepresentation(headerDiff.getRightLines(), otherDiffDisplayName,
				bodyDiff.getRightLines(), compositeRepresentation.footerLine), };
	}

}
