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
import java.util.*;

import docking.widgets.fieldpanel.field.AttributedString;
import docking.widgets.fieldpanel.field.CompositeAttributedString;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.template.*;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

public class PcodeFormatter {

	private static String EOL = System.getProperty("line.separator");

	private int maxDisplayLines = 0; // no-limit by default
	private boolean displayRawPcode = false;

	private FontMetrics metrics;

	private Color addressColor = OptionsGui.ADDRESS.getDefaultColor();
	private Color registerColor = OptionsGui.REGISTERS.getDefaultColor();
	private Color scalarColor = OptionsGui.CONSTANT.getDefaultColor();
	private Color localColor = OptionsGui.LABELS_LOCAL.getDefaultColor();

	AttributedString SPACE;
	AttributedString EQUALS;
	AttributedString COMMA;
	AttributedString LEFT_PAREN;
	AttributedString RIGHT_PAREN;
	AttributedString LEFT_BRACKET;
	AttributedString RIGHT_BRACKET;
	AttributedString STAR;
	AttributedString COLON;
	AttributedString QUOTE;

	/**
	 * Constructor
	 */
	public PcodeFormatter() {
		initPunctuation();
	}

	/**
	 * Set color options for AttributedString objects
	 * @param addressColor
	 * @param registerColor
	 * @param scalarColor
	 * @param localColor
	 */
	public void setColor(Color addressColor, Color registerColor, Color scalarColor,
			Color localColor) {
		this.addressColor = addressColor;
		this.registerColor = registerColor;
		this.scalarColor = scalarColor;
		this.localColor = localColor;
	}

	/**
	 * Set font metrics for AttributedString objects
	 * @param metrics
	 */
	public void setFontMetrics(FontMetrics metrics) {
		this.metrics = metrics;
		initPunctuation();
	}

	/**
	 * Set general formatting options
	 * @param maxDisplayLines
	 * @param displayRawPcode
	 */
	public void setOptions(int maxDisplayLines, boolean displayRawPcode) {
		this.maxDisplayLines = maxDisplayLines;
		this.displayRawPcode = displayRawPcode;
	}

	private void initPunctuation() {
		SPACE = new AttributedString(" ", Color.BLUE, metrics);
		EQUALS = new AttributedString(" = ", Color.BLUE, metrics);
		COMMA = new AttributedString(",", Color.BLUE, metrics);
		LEFT_PAREN = new AttributedString("(", Color.BLUE, metrics);
		RIGHT_PAREN = new AttributedString(")", Color.BLUE, metrics);
		LEFT_BRACKET = new AttributedString("[", Color.BLUE, metrics);
		RIGHT_BRACKET = new AttributedString("]", Color.BLUE, metrics);
		STAR = new AttributedString("*", Color.BLUE, metrics);
		COLON = new AttributedString(":", Color.BLUE, metrics);
		QUOTE = new AttributedString("\"", Color.BLUE, metrics);
	}

	/**
	 * Format an array of PcodeOp objects as a multi-line String
	 * @return pcode listing as a String
	 */
	public String toString(Program program, PcodeOp[] pcodeOps) {
		return toString(program, getPcodeOpTemplates(program.getAddressFactory(), pcodeOps));
	}

	/**
	 * Format an array of PcodeOp objects as a two-dimensional list of AttributedString objects.
	 * The returned list contains a separate element for each row of the pcode listing.
	 * @param program
	 * @param pcodeOps
	 * @return pcode listing as a two-dimensional list of AttributedString objects
	 */
	public List<AttributedString> toAttributedStrings(Program program, PcodeOp[] pcodeOps) {
		return toAttributedStrings(program,
			getPcodeOpTemplates(program.getAddressFactory(), pcodeOps));
	}

	/**
	 * Format an array of pcode OpTpl objects as a multi-line String
	 * @param program
	 * @param pcodeOpTemplates
	 * @return pcode listing as a String
	 */
	public String toString(Program program, OpTpl[] pcodeOpTemplates) {

		boolean indent = hasLabel(pcodeOpTemplates);
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < pcodeOpTemplates.length; i++) {
			if (maxDisplayLines > 0 && i >= maxDisplayLines) {
				break;
			}
			AttributedString line = formatOpTpl(program, pcodeOpTemplates[i], indent);
			if (buf.length() != 0) {
				buf.append(EOL);
			}
			buf.append(line.toString());
		}
		return buf.toString();
	}

	/**
	 * Format an array of pcode OpTpl objects as a list of AttributedString objects.
	 * The returned list contains a separate element for each row of the pcode listing.
	 * @param program
	 * @param pcodeOpTemplates
	 * @return pcode listing as a two-dimensional list of AttributedString objects
	 */
	public List<AttributedString> toAttributedStrings(Program program, OpTpl[] pcodeOpTemplates) {

		boolean indent = hasLabel(pcodeOpTemplates);

		ArrayList<AttributedString> list = new ArrayList<AttributedString>();
		for (int i = 0; i < pcodeOpTemplates.length; i++) {
			if (maxDisplayLines > 0 && i >= maxDisplayLines) {
				break;
			}
			list.add(formatOpTpl(program, pcodeOpTemplates[i], indent));
		}
		return list;

	}

	private AttributedString formatOpTpl(Program program, OpTpl op, boolean indent) {

		List<AttributedString> lineList = new ArrayList<AttributedString>();

		int opcode = op.getOpcode();
		if (PcodeOp.PTRADD == opcode) {
			// handle label OpTpl
			String label = "<" + op.getInput()[0].getOffset().getReal() + ">";
			lineList.add(new AttributedString(label, Color.BLUE, metrics));
			return new CompositeAttributedString(lineList);
		}

		if (indent) {
			lineList.add(SPACE);
			lineList.add(SPACE);
		}

		if (opcode >= PcodeOp.PCODE_MAX) {
			throw new RuntimeException("Unsupported opcode encountered: " + opcode);
		}
		VarnodeTpl output = op.getOutput();
		if (output != null) {
			formatVarnodeTpl(program, opcode, -1, output, lineList);
			lineList.add(EQUALS);
		}
		Color color = (opcode == PcodeOp.UNIMPLEMENTED) ? Color.RED : Color.BLUE.darker();
		lineList.add(new AttributedString(PcodeOp.getMnemonic(opcode), color, metrics));
		VarnodeTpl[] inputs = op.getInput();
		for (int i = 0; i < inputs.length; i++) {
			if (i > 0) {
				lineList.add(COMMA);
			}
			lineList.add(SPACE);
			if (i == 0) {
				if (!displayRawPcode) {
					if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
						formatMemoryInput(program, inputs[0], inputs[1], lineList);
						++i;
						continue;
					}
					if (opcode == PcodeOp.CALLOTHER) {
						formatCallOtherName(program.getLanguage(), inputs[0], lineList);
						continue;
					}
				}
				if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) {
					if (formatLabelInput(inputs[i], lineList)) {
						continue;
					}
				}
			}
			formatVarnodeTpl(program, opcode, i, inputs[i], lineList);
		}
		return new CompositeAttributedString(lineList);
	}

	private void formatVarnodeTpl(Program program, int opcode, int opIndex, VarnodeTpl vTpl,
			List<AttributedString> lineList) {

		ConstTpl space = vTpl.getSpace();
		ConstTpl offset = vTpl.getOffset();
		ConstTpl size = vTpl.getSize();

		if (space.getType() == ConstTpl.J_CURSPACE) {
			if (offset.getType() == ConstTpl.J_START) {
				lineList.add(new AttributedString("inst_start", localColor, metrics));
			}
			else if (offset.getType() == ConstTpl.J_NEXT) {
				lineList.add(new AttributedString("inst_next", localColor, metrics));
			}
			else {
				formatAddress(program, null, offset, size, lineList);
			}
		}
		else if (space.getType() == ConstTpl.SPACEID) {
			if (displayRawPcode && offset.getType() == ConstTpl.REAL &&
				size.getType() == ConstTpl.REAL) {
				formatRaw(space.getSpaceId(), offset, size, lineList);
			}
			else {
				if (space.isConstSpace()) {
					formatConstant(offset, size, lineList);
				}
				else if (space.isUniqueSpace()) {
					formatUnique(offset, size, lineList);
				}
				else {
					formatAddress(program, space.getSpaceId(), offset, size, lineList);
				}
			}
		}
		else {
			throw new RuntimeException("Unsupported space template type: " + space.getType());
		}
	}

	/**
	 * Format VarnodeTpl in a manner consistent with Varnode.toString().
	 * @param space address space
	 * @param offset offset of type ConstTpl.REAL
	 * @param size size of type ConstTpl.REAL
	 * @param lineList
	 */
	private void formatRaw(AddressSpace space, ConstTpl offset, ConstTpl size,
			List<AttributedString> lineList) {
		// same format as the Varnode.toString
		String str = "(" + space.getName() + ", 0x" + Long.toHexString(offset.getReal()) + ", " +
			size.getReal() + ")";
		lineList.add(new AttributedString(str, Color.BLUE, metrics));
	}

	private void formatUnique(ConstTpl offset, ConstTpl size, List<AttributedString> lineList) {
		if (offset.getType() != ConstTpl.REAL) {
			throw new RuntimeException("Unsupported unique offset type: " + offset.getType());
		}
		if (size.getType() != ConstTpl.REAL) {
			throw new RuntimeException("Unsupported unique size type: " + size.getType());
		}
		lineList.add(
			new AttributedString("$U" + Long.toHexString(offset.getReal()), localColor, metrics));
		formatSize(size, lineList);
	}

	private void formatAddress(Program program, AddressSpace addrSpace, ConstTpl offset,
			ConstTpl size, List<AttributedString> lineList) {
		if (offset.getType() != ConstTpl.REAL) {
			throw new RuntimeException("Unsupported address offset type: " + offset.getType());
		}

		long offsetValue = offset.getReal();
		if (addrSpace == null) {
			lineList.add(STAR);
			lineList.add(
				new AttributedString("0x" + Long.toHexString(offsetValue), addressColor, metrics));
			if (size.getType() != ConstTpl.J_CURSPACE_SIZE) {
				formatSize(size, lineList);
			}
			return;
		}

		int sizeValue = (int) size.getReal();
		Register reg = program.getRegister(addrSpace.getAddress(offsetValue), sizeValue);
		if (reg != null) {
			lineList.add(new AttributedString(reg.getName(), registerColor, metrics));
			if (reg.getMinimumByteSize() > sizeValue) {
				lineList.add(COLON);
				lineList.add(
					new AttributedString(Integer.toString(sizeValue), this.scalarColor, metrics));
			}
			return;
		}
		lineList.add(STAR);
		lineList.add(LEFT_BRACKET);
		lineList.add(new AttributedString(addrSpace.getName(), Color.BLUE, metrics));
		lineList.add(RIGHT_BRACKET);

		long wordOffset = offsetValue / addrSpace.getAddressableUnitSize();
		long offcut = offsetValue % addrSpace.getAddressableUnitSize();
		String str = "0x" + Long.toHexString(wordOffset);
		if (offcut != 0) {
			str += "." + offset;
		}
		lineList.add(new AttributedString(str, addressColor, metrics));
		formatSize(size, lineList);
	}

	private void formatConstant(ConstTpl offset, ConstTpl size, List<AttributedString> lineList) {
		if (offset.getType() != ConstTpl.REAL) {
			throw new RuntimeException("Unsupported constant offset type: " + offset.getType());
		}
		long value = offset.getReal();
		String valStr;
		if (value >= -64 && value <= 64) {
			valStr = Long.toString(value);
		}
		else {
			valStr = "0x" + Long.toHexString(value);
		}
		lineList.add(new AttributedString(valStr, scalarColor, metrics));
		formatSize(size, lineList);
	}

	private void formatSize(ConstTpl size, List<AttributedString> lineList) {
		if (size.getType() != ConstTpl.REAL) {
			throw new RuntimeException("Unsupported address size type: " + size.getType());
		}
		if (size.getReal() != 0) {
			lineList.add(COLON);
			lineList.add(new AttributedString(Long.toString(size.getReal()), scalarColor, metrics));
		}
	}

	private void formatCallOtherName(Language language, VarnodeTpl input0,
			List<AttributedString> lineList) {

		if (!input0.getSpace().isConstSpace() || input0.getOffset().getType() != ConstTpl.REAL) {
			throw new RuntimeException("Expected constant input[0] for CALLOTHER pcode op");
		}

		if (!(language instanceof SleighLanguage)) {
			throw new RuntimeException("Expected Sleigh language for CALLOTHER op");
		}

		int id = (int) input0.getOffset().getReal();
		String psuedoOp = ((SleighLanguage) language).getUserDefinedOpName(id);
		if (psuedoOp == null) {
			Msg.error(PcodeFormatter.class, "Psuedo-op index not found: " + id);
			psuedoOp = "unknown";
		}
		lineList.add(QUOTE);
		lineList.add(new AttributedString(psuedoOp, Color.BLUE, metrics));
		lineList.add(QUOTE);
	}

	private boolean formatLabelInput(VarnodeTpl input0, List<AttributedString> lineList) {
		if (input0.getSpace().isConstSpace() &&
			input0.getOffset().getType() == ConstTpl.J_RELATIVE) {
			String label = "<" + input0.getOffset().getReal() + ">";
			lineList.add(new AttributedString(label, Color.BLUE, metrics));
			return true;
		}
		return false;
	}

	private void formatMemoryInput(Program program, VarnodeTpl input0, VarnodeTpl input1,
			List<AttributedString> lineList) {
		if (!input0.getSpace().isConstSpace() || input0.getOffset().getType() != ConstTpl.REAL) {
			throw new RuntimeException("Expected constant input[0] for LOAD/STORE pcode op");
		}
		int id = (int) input0.getOffset().getReal();
		AddressSpace space = program.getAddressFactory().getAddressSpace(id);
		String spaceName;
		if (space == null) {
			Msg.error(PcodeFormatter.class, "Address space id not found: " + id);
			spaceName = "unknown";
		}
		else {
			spaceName = space.getName();
		}
		lineList.add(new AttributedString(spaceName, Color.BLUE, metrics));
		lineList.add(LEFT_PAREN);
		formatVarnodeTpl(program, -1, 1, input1, lineList);
		lineList.add(RIGHT_PAREN);
	}

	private boolean hasLabel(OpTpl[] pcodeOpTemplates) {
		for (OpTpl op : pcodeOpTemplates) {
			if (PcodeOp.PTRADD == op.getOpcode()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Convert flattened PcodeOp's into pcode operation templates.
	 * @param addrFactory
	 * @param pcodeOps
	 * @return pcode operation templates
	 */
	public OpTpl[] getPcodeOpTemplates(AddressFactory addrFactory, PcodeOp[] pcodeOps) {

		ArrayList<OpTpl> list = new ArrayList<OpTpl>();
		HashMap<Integer, Integer> labelMap = new HashMap<Integer, Integer>(); // label offset to index map

		for (PcodeOp pcodeOp : pcodeOps) {

			int opcode = pcodeOp.getOpcode();

			VarnodeTpl outputTpl = null;
			Varnode v = pcodeOp.getOutput();
			if (v != null) {
				outputTpl = getVarnodeTpl(addrFactory, v);
			}

			Varnode[] inputs = pcodeOp.getInputs();
			VarnodeTpl[] inputTpls = new VarnodeTpl[inputs.length];
			for (int i = 0; i < inputs.length; i++) {

				Varnode input = inputs[i];

				if (i == 0 && (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH)) {
					// Handle internal branch destination represented by constant destination
					if (input.isConstant()) {
						int labelOffset = pcodeOp.getSeqnum().getTime() + (int) input.getOffset();
						int labelIndex;
						if (labelMap.containsKey(labelOffset)) {
							labelIndex = labelMap.get(labelOffset);
						}
						else {
							labelIndex = labelMap.size();
							labelMap.put(labelOffset, labelIndex);
						}
						ConstTpl offsetTpl = new ConstTpl(ConstTpl.J_RELATIVE, labelIndex);
						ConstTpl spaceTpl = new ConstTpl(addrFactory.getConstantSpace());
						ConstTpl sizeTpl = new ConstTpl(ConstTpl.REAL, 8);
						inputTpls[i] = new VarnodeTpl(spaceTpl, offsetTpl, sizeTpl);
						continue;
					}
				}
				inputTpls[i] = getVarnodeTpl(addrFactory, input);
			}

			list.add(new OpTpl(opcode, outputTpl, inputTpls));
		}

		// Insert label templates from the bottom-up
		ArrayList<Integer> offsetList = new ArrayList<Integer>(labelMap.keySet());
		Collections.sort(offsetList);
		for (int i = offsetList.size() - 1; i >= 0; i--) {
			int labelOffset = offsetList.get(i);
			int labelIndex = labelMap.get(labelOffset);
			OpTpl labelTpl = getLabelOpTemplate(addrFactory, labelIndex);
			list.add(labelOffset, labelTpl);
		}

		OpTpl[] opTemplates = new OpTpl[list.size()];
		list.toArray(opTemplates);
		return opTemplates;
	}

	/**
	 * Create label OpTpl.
	 * Uses overloaded PcodeOp.PTRADD with input[0] = labelIndex
	 * @param addrFactory
	 * @param labelIndex
	 * @return label OpTpl
	 */
	private OpTpl getLabelOpTemplate(AddressFactory addrFactory, int labelIndex) {
		ConstTpl offsetTpl = new ConstTpl(ConstTpl.REAL, labelIndex);
		ConstTpl spaceTpl = new ConstTpl(addrFactory.getConstantSpace());
		ConstTpl sizeTpl = new ConstTpl(ConstTpl.REAL, 8);
		VarnodeTpl input = new VarnodeTpl(spaceTpl, offsetTpl, sizeTpl);
		return new OpTpl(PcodeOp.PTRADD, null, new VarnodeTpl[] { input });
	}

	private VarnodeTpl getVarnodeTpl(AddressFactory addrFactory, Varnode v) {
		ConstTpl offsetTpl = new ConstTpl(ConstTpl.REAL, v.getOffset());
		AddressSpace addressSpace = addrFactory.getAddressSpace(v.getSpace());
		if (addressSpace == null) {
			throw new IllegalArgumentException("Unknown varnode space ID: " + v.getSpace());
		}
		ConstTpl spaceTpl = new ConstTpl(addressSpace);
		ConstTpl sizeTpl = new ConstTpl(ConstTpl.REAL, v.getSize());
		return new VarnodeTpl(spaceTpl, offsetTpl, sizeTpl);
	}
}
