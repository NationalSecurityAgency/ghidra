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
package ghidra.app.util.viewer.field;

import java.awt.Color;
import java.math.BigInteger;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Mask;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.InstructionMaskValueFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.StringUtilities;

public class InstructionMaskValueFieldFactory extends FieldFactory {

	public static final String FIELD_NAME = "Instr Mask/Value";
	public static final Color MASK_COLOR = new Color(0, 0, 128);
	public static final Color VALUE_COLOR = new Color(0, 128, 0);
	public static final Color LABEL_COLOR = new Color(0, 0, 0);

	/**
	 * Default constructor.
	 */
	public InstructionMaskValueFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hsProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private InstructionMaskValueFieldFactory(FieldFormatModel model, HighlightProvider hsProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hsProvider, displayOptions, fieldOptions);
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		// stub
	}

	/**
	 * Returns the FactoryField for the given object at index index.
	 * @param varWidth the amount of variable width spacing for any fields
	 * before this one.
	 * @param proxy the object whose properties should be displayed.
	 */
	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();

		if (!enabled || !(obj instanceof Instruction)) {
			return null;
		}
		Instruction instr = (Instruction) obj;
		InstructionPrototype proto = instr.getPrototype();
		int operandCount = proto.getNumOperands();
		Mask instructionMask = proto.getInstructionMask();
		if (instructionMask == null) {
			return null;
		}
		Mask[] operandMasks = new Mask[operandCount];
		for (int i = 0; i < operandCount; i++) {
			operandMasks[i] = proto.getOperandValueMask(i);
			if (operandMasks[i] == null) {
				// disable operand mask display
				operandCount = 0;
				break;
			}
		}

		try {
			FieldElement[] fieldElements = new FieldElement[2 * (operandCount + 1)];
			fieldElements[0] =
				getLine("M[m]: ", instructionMask.getBytes(), MASK_COLOR, proxy, varWidth);
			fieldElements[1] =
				getLine("V[m]: ", instructionMask.applyMask(instr), VALUE_COLOR, proxy, varWidth);
			for (int i = 0; i < operandCount; i++) {
				fieldElements[2 * (i + 1)] = getLine("M[" + i + "]: ", operandMasks[i].getBytes(),
					MASK_COLOR, proxy, varWidth);
				fieldElements[2 * (i + 1) + 1] = getLine("V[" + i + "]: ",
					operandMasks[i].applyMask(instr), VALUE_COLOR, proxy, varWidth);
			}

			return ListingTextField.createMultilineTextField(this, proxy, fieldElements,
				startX + varWidth, width, fieldElements.length, hlProvider);
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	private FieldElement getLine(String label, byte[] value, Color valueColor, ProxyObj<?> proxy,
			int varWidth) {

		FieldElement[] fieldElements = new FieldElement[2];
		AttributedString as =
			new AttributedString(label, LABEL_COLOR, getMetrics(), false, underlineColor);
		fieldElements[0] = new TextFieldElement(as, 0, 0);
		as = new AttributedString(getFormattedBytes(value), valueColor, getMetrics(), false,
			underlineColor);
		fieldElements[1] = new TextFieldElement(as, 0, 0);
		return new CompositeFieldElement(fieldElements);
	}

	private String getFormattedBytes(byte[] value) {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < value.length; i++) {
			String byteStr = StringUtilities.pad(Integer.toBinaryString(value[i] & 0xff), '0', 8);
			buf.append(byteStr);
			if (i < (value.length - 1)) {
				buf.append(".");
			}
		}
		return buf.toString();
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getProgramLocation(int, int, ghidra.app.util.viewer.field.ListingField)
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof Instruction)) {
			return null;
		}
		Instruction instr = (Instruction) obj;

		return new InstructionMaskValueFieldLocation(instr.getProgram(), instr.getMinAddress(), row,
			col);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {
		if (programLoc instanceof InstructionMaskValueFieldLocation) {
			InstructionMaskValueFieldLocation maskValueLoc =
				(InstructionMaskValueFieldLocation) programLoc;
			return new FieldLocation(index, fieldNum, maskValueLoc.getRow(),
				maskValueLoc.getCharOffset());
		}
		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#acceptsType(int, java.lang.Class)
	 */
	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return category == FieldFormatModel.INSTRUCTION_OR_DATA;
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider hsProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new InstructionMaskValueFieldFactory(formatModel, hsProvider, displayOptions,
			fieldOptions);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getDefaultColor()
	 */
	@Override
	public Color getDefaultColor() {
		return Color.black;
	}
}
