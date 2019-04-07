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
package ghidra.app.plugin.processors.generic;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.pcode.PcodeFormatter;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.*;
import ghidra.program.util.PcodeFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * Pcode field factory.
 */
public class PcodeFieldFactory extends FieldFactory {

	public static final String FIELD_NAME = "PCode";

	private final static String GROUP_TITLE = "Pcode Field";
	public final static String MAX_DISPLAY_LINES_MSG =
		GROUP_TITLE + Options.DELIMITER + "Maximum Lines To Display";
	public static final String DISPLAY_RAW_PCODE =
		GROUP_TITLE + Options.DELIMITER + "Display Raw Pcode";
	public final static int MAX_DISPLAY_LINES = 30;

	private PcodeFormatter formatter;

	public PcodeFieldFactory() {
		super(FIELD_NAME);
		setWidth(300);
	}

	public PcodeFieldFactory(String name, FieldFormatModel model,
			HighlightProvider highlightProvider, Options displayOptions, Options fieldOptions) {

		super(name, model, highlightProvider, displayOptions, fieldOptions);
		setWidth(300);
		color = displayOptions.getColor(OptionsGui.BYTES.getColorOptionName(),
			OptionsGui.BYTES.getDefaultColor());
		style = displayOptions.getInt(OptionsGui.BYTES.getStyleOptionName(), -1);
		formatter = new PcodeFormatter();

		setColors(displayOptions);
		setOptions(fieldOptions);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel myModel, HighlightProvider highlightProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new PcodeFieldFactory(FIELD_NAME, myModel, highlightProvider, displayOptions,
			fieldOptions);
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();

		if (!enabled || !(obj instanceof Instruction)) {
			return null;
		}
		Instruction instr = (Instruction) obj;

		ArrayList<TextFieldElement> elements = new ArrayList<>();

		List<AttributedString> pcodeListing =
			formatter.toAttributedStrings(instr.getProgram(), instr.getPcode(true));
		int lineCnt = pcodeListing.size();
		for (int i = 0; i < lineCnt; i++) {
			elements.add(new TextFieldElement(pcodeListing.get(i), i, 0));
		}

		if (elements.size() > 0) {
			FieldElement[] textElements = elements.toArray(new FieldElement[elements.size()]);
			return ListingTextField.createMultilineTextField(this, proxy, textElements,
				startX + varWidth, width, Integer.MAX_VALUE, hlProvider);
		}
		return null;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (loc instanceof PcodeFieldLocation) {
			return new FieldLocation(index, fieldNum, ((PcodeFieldLocation) loc).getRow(),
				((PcodeFieldLocation) loc).getCharOffset());
		}
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField listingField) {
		ProxyObj<?> proxy = listingField.getProxy();
		Object obj = proxy.getObject();

		if (!(obj instanceof Instruction)) {
			return null;
		}

		if (row < 0 || col < 0) {
			return null;
		}

		Instruction instr = (Instruction) obj;
		Program program = instr.getProgram();

		List<AttributedString> attributedStrings =
			formatter.toAttributedStrings(program, instr.getPcode(true));
		List<String> strings = new ArrayList<>(attributedStrings.size());
		for (AttributedString attributedString : attributedStrings) {
			strings.add(attributedString.getText());
		}

		return new PcodeFieldLocation(program, instr.getMinAddress(), strings, row, col);
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return (CodeUnit.class.isAssignableFrom(proxyObjectClass) &&
			(category == FieldFormatModel.INSTRUCTION_OR_DATA ||
				category == FieldFormatModel.OPEN_DATA));
	}

	@Override
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.displayOptionsChanged(options, optionName, oldValue, newValue);
		formatter.setFontMetrics(getMetrics());
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.fieldOptionsChanged(options, optionName, oldValue, newValue);

		if (options.getName().equals(GhidraOptions.CATEGORY_BROWSER_FIELDS)) {
			if (optionName.equals(MAX_DISPLAY_LINES_MSG) || optionName.equals(DISPLAY_RAW_PCODE)) {
				setOptions(options);
				model.update();
			}
		}
	}

	/**
	 * Called when the fonts are first initialized or when one of the options
	 * changes.  It looks up all the color settings and resets the its values.
	 */
	private void setColors(Options options) {
		formatter.setColor(
			options.getColor(OptionsGui.ADDRESS.getColorOptionName(),
				OptionsGui.ADDRESS.getDefaultColor()),
			options.getColor(OptionsGui.REGISTERS.getColorOptionName(),
				OptionsGui.REGISTERS.getDefaultColor()),
			options.getColor(OptionsGui.CONSTANT.getColorOptionName(),
				OptionsGui.CONSTANT.getDefaultColor()),
			options.getColor(OptionsGui.LABELS_LOCAL.getColorOptionName(),
				OptionsGui.LABELS_LOCAL.getDefaultColor()));
		formatter.setFontMetrics(getMetrics());
	}

	private void setOptions(Options fieldOptions) {
		fieldOptions.registerOption(MAX_DISPLAY_LINES_MSG, MAX_DISPLAY_LINES, null,
			"Max number line of pcode to display");
		fieldOptions.registerOption(DISPLAY_RAW_PCODE, false, null,
			"Display raw pcode (for debugging)");
		int maxDisplayLines = fieldOptions.getInt(MAX_DISPLAY_LINES_MSG, MAX_DISPLAY_LINES);
		boolean displayRaw = fieldOptions.getBoolean(DISPLAY_RAW_PCODE, false);
		formatter.setOptions(maxDisplayLines, displayRaw);
	}

}
