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
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;

public class AttributedStringPcodeFormatter extends
		AbstractPcodeFormatter<List<AttributedString>, AttributedStringPcodeFormatter.ToAttributedStringsAppender> {

	private int maxDisplayLines = 0; // no-limit by default
	private boolean displayRawPcode = false;

	private FontMetrics metrics;

	private Color addressColor = OptionsGui.ADDRESS.getDefaultColor();
	private Color registerColor = OptionsGui.REGISTERS.getDefaultColor();
	private Color scalarColor = OptionsGui.CONSTANT.getDefaultColor();
	private Color localColor = OptionsGui.LABELS_LOCAL.getDefaultColor();
	private Color mnemonicColor = OptionsGui.MNEMONIC.getDefaultColor();
	private Color unimplColor = OptionsGui.UNIMPL.getDefaultColor();
	private Color separatorColor = OptionsGui.SEPARATOR.getDefaultColor();
	private Color lineLabelColor = OptionsGui.PCODE_LINE_LABEL.getDefaultColor();
	private Color spaceColor = OptionsGui.PCODE_ADDR_SPACE.getDefaultColor();
	private Color rawColor = OptionsGui.PCODE_RAW_VARNODE.getDefaultColor();
	private Color useropColor = OptionsGui.PCODE_USEROP.getDefaultColor();

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
	 * Set the color for addresses
	 * 
	 * @param addressColor
	 */
	public void setAddressColor(Color addressColor) {
		this.addressColor = addressColor;
	}

	/**
	 * Set the color for register names
	 * 
	 * @param registerColor
	 */
	public void setRegisterColor(Color registerColor) {
		this.registerColor = registerColor;
	}

	/**
	 * Set the color for scalars and non-address constants
	 * 
	 * @param scalarColor
	 */
	public void setScalarColor(Color scalarColor) {
		this.scalarColor = scalarColor;
	}

	/**
	 * Set the color for labels referring to addresses
	 * 
	 * @param localColor
	 */
	public void setLocalColor(Color localColor) {
		this.localColor = localColor;
	}

	/**
	 * Set the color for op mnemonics
	 * 
	 * @param mnemonicColor
	 */
	public void setMnemonicColor(Color mnemonicColor) {
		this.mnemonicColor = mnemonicColor;
	}

	/**
	 * Set the color for the {@code unimpl} op mnemonic
	 * 
	 * @param unimplColor
	 */
	public void setUnimplColor(Color unimplColor) {
		this.unimplColor = unimplColor;
	}

	/**
	 * Set the color for punctuation
	 * 
	 * @param separatorColor
	 */
	public void setSeparatorColor(Color separatorColor) {
		this.separatorColor = separatorColor;
		initPunctuation();
	}

	/**
	 * Set the color for labels referring to p-code ops
	 * 
	 * @param lineLabelColor
	 */
	public void setLineLabelColor(Color lineLabelColor) {
		this.lineLabelColor = lineLabelColor;
	}

	/**
	 * Set the color for address space names
	 * 
	 * @param spaceColor
	 */
	public void setSpaceColor(Color spaceColor) {
		this.spaceColor = spaceColor;
	}

	/**
	 * Set the color for raw varnodes
	 * 
	 * @param rawColor
	 */
	public void setRawColor(Color rawColor) {
		this.rawColor = rawColor;
	}

	/**
	 * Set the color for userop ({@code CALLOTHER}) names
	 * 
	 * @param useropColor
	 */
	public void setUseropColor(Color useropColor) {
		this.useropColor = useropColor;
	}

	/**
	 * Set font metrics for AttributedString objects
	 * 
	 * @param metrics
	 */
	public void setFontMetrics(FontMetrics metrics) {
		this.metrics = metrics;
		initPunctuation();
	}

	/**
	 * Set general formatting options
	 * 
	 * @param maxDisplayLines
	 * @param displayRawPcode
	 */
	public void setOptions(int maxDisplayLines, boolean displayRawPcode) {
		this.maxDisplayLines = maxDisplayLines;
		this.displayRawPcode = displayRawPcode;
	}

	private void initPunctuation() {
		aSpace = new AttributedString(" ", separatorColor, metrics);
		aEquals = new AttributedString(" = ", separatorColor, metrics);
		aComma = new AttributedString(",", separatorColor, metrics);
		aLeftParen = new AttributedString("(", separatorColor, metrics);
		aRightParen = new AttributedString(")", separatorColor, metrics);
		aLeftBracket = new AttributedString("[", separatorColor, metrics);
		aRightBracket = new AttributedString("]", separatorColor, metrics);
		aStar = new AttributedString("*", separatorColor, metrics);
		aColon = new AttributedString(":", separatorColor, metrics);
		aQuote = new AttributedString("\"", separatorColor, metrics);
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
			lineList.add(new AttributedString(stringifyLineLabel(label), lineLabelColor, metrics));
		}

		@Override
		public void appendMnemonic(int opcode) {
			Color color = opcode == PcodeOp.UNIMPLEMENTED ? unimplColor : mnemonicColor;
			lineList.add(new AttributedString(stringifyOpMnemonic(opcode), color, metrics));
		}

		@Override
		public void appendUserop(int id) {
			lineList.add(new AttributedString(stringifyUserop(language, id), useropColor, metrics));
		}

		@Override
		public void appendRawVarnode(AddressSpace space, long offset, long size) {
			lineList.add(new AttributedString(stringifyRawVarnode(space, offset, size), rawColor,
				metrics));
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
			lineList.add(new AttributedString(stringifyWordOffcut(wordOffset, offcut), addressColor,
				metrics));
		}

		@Override
		public void appendLabel(String label) {
			lineList.add(new AttributedString(label, localColor, metrics));
		}

		@Override
		public void appendRegister(Register register) {
			lineList.add(new AttributedString(stringifyRegister(register), registerColor, metrics));
		}

		@Override
		public void appendScalar(long value) {
			lineList.add(new AttributedString(stringifyScalarValue(value), scalarColor, metrics));
		}

		@Override
		public void appendSpace(AddressSpace space) {
			lineList.add(new AttributedString(stringifySpace(space), spaceColor, metrics));
		}

		@Override
		public void appendUnique(long offset) {
			lineList.add(new AttributedString(stringifyUnique(offset), localColor, metrics));
		}

		@Override
		public List<AttributedString> finish() {
			return list;
		}
	}
}
