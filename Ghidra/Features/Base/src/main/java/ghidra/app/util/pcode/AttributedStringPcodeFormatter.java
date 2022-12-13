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
package ghidra.app.util.pcode;

import java.awt.Color;
import java.awt.FontMetrics;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.field.AttributedString;
import docking.widgets.fieldpanel.field.CompositeAttributedString;
import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.app.util.viewer.field.ListingColors;
import ghidra.app.util.viewer.field.ListingColors.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;

public class AttributedStringPcodeFormatter extends
		AbstractPcodeFormatter<List<AttributedString>, AttributedStringPcodeFormatter.ToAttributedStringsAppender> {

	private int maxDisplayLines = 0; // no-limit by default
	private boolean displayRawPcode = false;

	private FontMetrics metrics;

	private AttributedString aSpace;
	private AttributedString aEquals;
	private AttributedString aComma;
	private AttributedString aLeftParen;
	private AttributedString aRightParen;
	private AttributedString aLeftBracket;
	private AttributedString aRightBracket;
	private AttributedString aStar;
	private AttributedString aColon;
	private AttributedString aQuote;

	/**
	 * Constructor
	 */
	public AttributedStringPcodeFormatter() {
		initPunctuation();
	}

	/**
	 * Set font metrics for AttributedString objects
	 * 
	 * @param metrics the font metrics
	 */
	public void setFontMetrics(FontMetrics metrics) {
		this.metrics = metrics;
		initPunctuation();
	}

	/**
	 * Set general formatting options
	 * 
	 * @param maxDisplayLines the maximum number of lines to display
	 * @param displayRawPcode show raw pcode
	 */
	public void setOptions(int maxDisplayLines, boolean displayRawPcode) {
		this.maxDisplayLines = maxDisplayLines;
		this.displayRawPcode = displayRawPcode;
	}

	private void initPunctuation() {
		aSpace = new AttributedString(" ", ListingColors.SEPARATOR, metrics);
		aEquals = new AttributedString(" = ", ListingColors.SEPARATOR, metrics);
		aComma = new AttributedString(",", ListingColors.SEPARATOR, metrics);
		aLeftParen = new AttributedString("(", ListingColors.SEPARATOR, metrics);
		aRightParen = new AttributedString(")", ListingColors.SEPARATOR, metrics);
		aLeftBracket = new AttributedString("[", ListingColors.SEPARATOR, metrics);
		aRightBracket = new AttributedString("]", ListingColors.SEPARATOR, metrics);
		aStar = new AttributedString("*", ListingColors.SEPARATOR, metrics);
		aColon = new AttributedString(":", ListingColors.SEPARATOR, metrics);
		aQuote = new AttributedString("\"", ListingColors.SEPARATOR, metrics);
	}

	@Override
	protected ToAttributedStringsAppender createAppender(Language language, boolean indent) {
		return new ToAttributedStringsAppender(language, indent);
	}

	@Override
	public boolean isFormatRaw() {
		return displayRawPcode;
	}

	@Override
	protected FormatResult formatOpTemplate(ToAttributedStringsAppender appender, OpTpl op) {
		if (maxDisplayLines > 0 && appender.getLineCount() >= maxDisplayLines) {
			return FormatResult.TERMINATE;
		}
		appender.startLine();
		FormatResult result = super.formatOpTemplate(appender, op);
		appender.endLine();
		return result;
	}

	class ToAttributedStringsAppender extends AbstractAppender<List<AttributedString>> {
		private final List<AttributedString> list = new ArrayList<>();
		private List<AttributedString> lineList; // contents of one line

		public ToAttributedStringsAppender(Language language, boolean indent) {
			super(language, indent);
		}

		int getLineCount() {
			return list.size();
		}

		void startLine() {
			lineList = new ArrayList<>();
		}

		void endLine() {
			list.add(new CompositeAttributedString(lineList));
		}

		@Override
		public void appendLineLabelRef(long label) {
			lineList.add(
				new AttributedString(stringifyLineLabel(label), PcodeColors.LABEL, metrics));
		}

		@Override
		public void appendMnemonic(int opcode) {
			Color color = opcode == PcodeOp.UNIMPLEMENTED ? MnemonicColors.UNIMPLEMENTED
					: MnemonicColors.NORMAL;
			lineList.add(new AttributedString(stringifyOpMnemonic(opcode), color, metrics));
		}

		@Override
		public void appendUserop(int id) {
			lineList.add(
				new AttributedString(stringifyUserop(language, id), PcodeColors.USEROP, metrics));
		}

		@Override
		public void appendRawVarnode(AddressSpace space, long offset, long size) {
			lineList.add(new AttributedString(stringifyRawVarnode(space, offset, size),
				PcodeColors.VARNODE, metrics));
		}

		private AttributedString getAttributedChar(char c) {
			switch (c) {
				case ' ':
					return aSpace;
				case '=':
					return aEquals;
				case ',':
					return aComma;
				case '(':
					return aLeftParen;
				case ')':
					return aRightParen;
				case '[':
					return aLeftBracket;
				case ']':
					return aRightBracket;
				case '*':
					return aStar;
				case ':':
					return aColon;
				case '"':
					return aQuote;
				default:
					throw new AssertionError();
			}
		}

		@Override
		public void appendCharacter(char c) {
			lineList.add(getAttributedChar(c));
		}

		@Override
		public void appendAddressWordOffcut(long wordOffset, long offcut) {
			lineList.add(new AttributedString(stringifyWordOffcut(wordOffset, offcut),
				ListingColors.ADDRESS, metrics));
		}

		@Override
		public void appendLabel(String label) {
			lineList.add(new AttributedString(label, LabelColors.LOCAL, metrics));
		}

		@Override
		public void appendRegister(Register register) {
			lineList.add(
				new AttributedString(stringifyRegister(register), ListingColors.REGISTER, metrics));
		}

		@Override
		public void appendScalar(long value) {
			lineList.add(
				new AttributedString(stringifyScalarValue(value), ListingColors.CONSTANT, metrics));
		}

		@Override
		public void appendSpace(AddressSpace space) {
			lineList.add(
				new AttributedString(stringifySpace(space), PcodeColors.ADDRESS_SPACE, metrics));
		}

		@Override
		public void appendUnique(long offset) {
			lineList.add(new AttributedString(stringifyUnique(offset), LabelColors.LOCAL, metrics));
		}

		@Override
		public List<AttributedString> finish() {
			return list;
		}
	}
}
