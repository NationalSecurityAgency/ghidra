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
/*
 * BytesFieldFactory.java
 *
 * Created on June 18, 2001, 11:01 AM
 */

package ghidra.app.util.viewer.field;

import java.awt.Color;
import java.math.BigInteger;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.BytesFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
  *  Generates Bytes Fields.
  */
public class BytesFieldFactory extends FieldFactory {
	private static final int CHARS_IN_BYTE = 2;
	public static final String FIELD_NAME = "Bytes";
	public static final Color DEFAULT_COLOR = Color.BLUE;
	public static final Color ALIGNMENT_BYTES_COLOR = Color.gray;
	public final static String GROUP_TITLE = "Bytes Field";
	public final static String MAX_DISPLAY_LINES_MSG =
		GROUP_TITLE + Options.DELIMITER + "Maximum Lines To Display";
	public final static String DELIMITER_MSG = GROUP_TITLE + Options.DELIMITER + "Delimiter";
	public final static String BYTE_GROUP_SIZE_MSG =
		GROUP_TITLE + Options.DELIMITER + "Byte Group Size";
	public final static String DISPLAY_UCASE_MSG =
		GROUP_TITLE + Options.DELIMITER + "Display in Upper Case";
	public final static String REVERSE_INSTRUCTION_BYTE_ORDERING =
		GROUP_TITLE + Options.DELIMITER + "Reverse Instruction Byte Ordering";
	public final static String DISPLAY_STRUCTURE_ALIGNMENT_BYTES_MSG =
		GROUP_TITLE + Options.DELIMITER + "Display Structure Alignment Bytes";

	private String delim = " ";
	private int maxDisplayLines;
	/** number of bytes (not chars) displayed without whitespace; usually 1*/
	private int byteGroupSize;
	private boolean displayUpperCase;
	private boolean reverseInstByteOrdering;
	private boolean displayStructureAlignmentBytes;

	/**
	 * Default Constructor
	 */
	public BytesFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hsProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private BytesFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);

		HelpLocation hl = new HelpLocation("CodeBrowserPlugin", "Bytes_Field");
		fieldOptions.getOptions(GROUP_TITLE).setOptionsHelpLocation(hl);

		fieldOptions.registerOption(DELIMITER_MSG, " ", hl,
			"String used to separate groups of bytes in the bytes field.");
		fieldOptions.registerOption(MAX_DISPLAY_LINES_MSG, 3, hl,
			"The maximum number of lines used to display bytes.");
		fieldOptions.registerOption(BYTE_GROUP_SIZE_MSG, 1, hl,
			"The number of bytes to group together without delimeters in the bytes field.");
		fieldOptions.registerOption(DISPLAY_UCASE_MSG, false, hl,
			"Displays the hex digits in upper case in the bytes field");
		fieldOptions.registerOption(REVERSE_INSTRUCTION_BYTE_ORDERING, false, hl,
			"Reverses the normal order of the bytes in the bytes field." +
				"  Only used for instructions in Little Endian format");
		fieldOptions.registerOption(DISPLAY_STRUCTURE_ALIGNMENT_BYTES_MSG, true, hl,
			"Display trailing alignment bytes in structures.");

		delim = fieldOptions.getString(DELIMITER_MSG, " ");
		maxDisplayLines = fieldOptions.getInt(MAX_DISPLAY_LINES_MSG, 3);
		byteGroupSize = fieldOptions.getInt(BYTE_GROUP_SIZE_MSG, 1);
		displayUpperCase = fieldOptions.getBoolean(DISPLAY_UCASE_MSG, false);
		reverseInstByteOrdering = fieldOptions.getBoolean(REVERSE_INSTRUCTION_BYTE_ORDERING, false);
		displayStructureAlignmentBytes =
			fieldOptions.getBoolean(DISPLAY_STRUCTURE_ALIGNMENT_BYTES_MSG, false);
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {

		if (optionName.equals(MAX_DISPLAY_LINES_MSG)) {
			setDisplayLines(((Integer) newValue).intValue(), options);
			model.update();
		}
		else if (optionName.equals(DELIMITER_MSG)) {
			setDelim((String) newValue, options);
			model.update();
		}
		else if (optionName.equals(BYTE_GROUP_SIZE_MSG)) {
			setGroupSize(((Integer) newValue).intValue(), options);
			model.update();
		}
		else if (optionName.equals(DISPLAY_UCASE_MSG)) {
			displayUpperCase = ((Boolean) newValue).booleanValue();
			model.update();
		}
		else if (optionName.equals(REVERSE_INSTRUCTION_BYTE_ORDERING)) {
			reverseInstByteOrdering = ((Boolean) newValue).booleanValue();
			model.update();
		}
		else if (optionName.equals(DISPLAY_STRUCTURE_ALIGNMENT_BYTES_MSG)) {
			displayStructureAlignmentBytes = ((Boolean) newValue).booleanValue();
			model.update();
		}
	}

	private void setGroupSize(int n, Options options) {
		if (n < 1) {
			n = 1;
			options.setInt(BYTE_GROUP_SIZE_MSG, 1);
		}
		byteGroupSize = n;
	}

	private void setDisplayLines(int n, Options options) {
		if (n < 1) {
			n = 1;
			options.setInt(MAX_DISPLAY_LINES_MSG, 1);
		}
		maxDisplayLines = n;
	}

	private void setDelim(String s, Options options) {
		if (s == null) {
			s = " ";
			options.setString(DELIMITER_MSG, s);
		}
		delim = s;
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;

		int length = Math.min(cu.getLength(), 100);
		byte[] bytes = new byte[length];
		try {
			length = cu.getProgram().getMemory().getBytes(cu.getAddress(), bytes);
		}
		catch (MemoryAccessException e) {
			return null;
		}
		if (length == 0) {
			return null;
		}

		if ((cu instanceof Instruction) && reverseInstByteOrdering &&
			!cu.getProgram().getMemory().isBigEndian()) {
			int i = 0;
			int j = length - 1;
			while (j > i) {
				byte b = bytes[i];
				bytes[i++] = bytes[j];
				bytes[j--] = b;
			}
		}

		int fieldElementLength = length / byteGroupSize;
		int residual = length % byteGroupSize;
		if (residual != 0) {
			fieldElementLength++;
		}
		boolean wasTruncated = length != cu.getLength();

		byte[] alignmentBytes = getAlignmentBytes(cu, wasTruncated);
		int extraLen = getLengthForAlignmentBytes(alignmentBytes, residual);

		FieldElement[] aStrings = new FieldElement[fieldElementLength + extraLen];

		buildAttributedByteValues(aStrings, 0, bytes, length, 0, color, extraLen != 0);
		if (extraLen != 0) {
			buildAttributedByteValues(aStrings, fieldElementLength, alignmentBytes,
				alignmentBytes.length, residual, ALIGNMENT_BYTES_COLOR, false);
		}

		return ListingTextField.createPackedTextField(this, proxy, aStrings, startX + varWidth,
			width, maxDisplayLines, hlProvider);
	}

	private int getLengthForAlignmentBytes(byte[] alignmentBytes, int residual) {
		if (alignmentBytes == null) {
			return 0;
		}
		int firstGroup = byteGroupSize - residual;
		int extraBytes = alignmentBytes.length - firstGroup;
		if (extraBytes < 0) {
			return 1;
		}
		int alignmentLength = (extraBytes / byteGroupSize) + 1;
		if (extraBytes % byteGroupSize != 0) {
			alignmentLength++;
		}
		return alignmentLength;
	}

	private byte[] getAlignmentBytes(CodeUnit cu, boolean wasTruncated) {
		if ((cu instanceof Data) && displayStructureAlignmentBytes && !wasTruncated) {
			return getStructureComponentAlignmentBytes((Data) cu);
		}
		return null;
	}

	private int buildAttributedByteValues(FieldElement[] aStrings, int pos, byte[] bytes, int size,
			int residual, Color c, boolean addDelimToLastGroup) {
		StringBuffer buffer = new StringBuffer();
		int groupSize = byteGroupSize - residual;
		int tempGroupSize = 0;
		for (int i = 0; i < size; ++i) {
			if (bytes[i] >= 0x00 && bytes[i] <= 0x0F) {
				buffer.append("0");
			}
			String bStr = Integer.toHexString(bytes[i] & 0x000000FF);
			if (bStr.length() > 2) {
				bStr = bStr.substring(bStr.length() - 2);
			}
			if (displayUpperCase) {
				bStr = bStr.toUpperCase();
			}
			buffer.append(bStr);
			++tempGroupSize;
			if (tempGroupSize == groupSize) {
				tempGroupSize = 0;
				groupSize = byteGroupSize;
				if (i < size - 1 || addDelimToLastGroup) {
					buffer.append(delim);
				}
				AttributedString as = new AttributedString(buffer.toString(), c, getMetrics());
				aStrings[pos] = new TextFieldElement(as, pos, 0);
				pos++;
				buffer = new StringBuffer();
			}
		}
		// append incomplete byte group...
		if (tempGroupSize > 0) {
			AttributedString as = new AttributedString(buffer.toString(), c, getMetrics());
			aStrings[pos] = new TextFieldElement(as, pos, 0);
		}
		return tempGroupSize;
	}

	private byte[] getStructureComponentAlignmentBytes(Data data) {

		Data parent = data.getParent();
		if (parent == null) {
			return null;
		}
		DataType baseDataType = parent.getBaseDataType();
		if (!(baseDataType instanceof Structure)) {
			return null; // e.g., union
		}
		Structure struct = (Structure) baseDataType;
		if (!struct.isPackingEnabled()) {
			return null;
		}

		int alignSize = 0;
		int ordinal = data.getComponentIndex();
		if (ordinal == (struct.getNumComponents() - 1)) {
			alignSize = (int) (parent.getMaxAddress().subtract(data.getMaxAddress()));
		}
		else {
			Data nextComponent = parent.getComponent(ordinal + 1);
			if (nextComponent == null) {
				return null; // this should never happen
			}
			alignSize = (int) (nextComponent.getMinAddress().subtract(data.getMaxAddress())) - 1;
		}
		if (alignSize <= 0) {
			return null;
		}
		int alignmentOffset = data.getParentOffset() + data.getLength();

		byte[] bytes = new byte[alignSize];
		parent.getBytes(bytes, alignmentOffset);
		return bytes;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit) || row < 0 || col < 0) {
			return null;
		}

		CodeUnit cu = (CodeUnit) obj;

		int[] cpath = null;
		if (cu instanceof Data) {
			cpath = ((Data) cu).getComponentPath();
		}

		ListingTextField btf = (ListingTextField) bf;
		RowColLocation fieldLoc = btf.screenToDataLocation(row, col);
		int tokenIndex = fieldLoc.row();
		int tokenCharPos = fieldLoc.col();

		// compute tokens associated with code unit bytes (excluding trailing alignment bytes)
		int size = cu.getLength();
		int len = size / byteGroupSize;
		int residual = size % byteGroupSize;
		if (residual != 0) {
			len++;
		}

		// compensate for split group containing optional alignment bytes
		if (tokenIndex >= len && residual != 0) {
			if (tokenIndex == len) {
				tokenCharPos += residual * CHARS_IN_BYTE;
			}
			--tokenIndex;
		}

		int byteIndex = tokenIndex * byteGroupSize + getByteIndexInToken(tokenCharPos);
		int charOffset = computeCharOffset(tokenCharPos);

		return new BytesFieldLocation(cu.getProgram(), cu.getMinAddress(),
			cu.getMinAddress().add(byteIndex), cpath, charOffset);
	}

	/**
	 *  Computes how many bytes the the given column position represents. Normally
	 *  this is just the  column position / 2 (since each byte consists of two chars).  There
	 *  is a special case when the col position is just past the last char of the token.  In
	 *  this case, we want to return the number of bytes in a token - 1;
	 */
	private int getByteIndexInToken(int col) {
		if (col >= byteGroupSize * CHARS_IN_BYTE) {
			return byteGroupSize - 1;
		}
		return col / CHARS_IN_BYTE;
	}

	/**
	 * Computes the character offset for a BytesFieldLocation based on the character column the
	 * cursor is at in the token.  BytesFieldLocation character offsets are always as if the group size is 1.
	 * So for all positions except the last byte, it is just the column modulo 2.  For the last byte, we have
	 * to account for any columns past the last char.  In this case, we have to subtract off
	 * 2 for every byte before the last byte.
	 *
	 */
	private int computeCharOffset(int col) {
		if (col >= byteGroupSize * CHARS_IN_BYTE) {
			return col - ((byteGroupSize - 1) * CHARS_IN_BYTE);
		}
		return col % CHARS_IN_BYTE;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		if (!(loc instanceof BytesFieldLocation)) {
			return null;
		}

		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}

		CodeUnit cu = (CodeUnit) obj;

		BytesFieldLocation bytesLoc = (BytesFieldLocation) loc;
		int byteIndex = bytesLoc.getByteIndex();
		int columnInByte = bytesLoc.getColumnInByte();

		int size = cu.getLength();
		int residual = size % byteGroupSize;

		if (!displayStructureAlignmentBytes && byteIndex >= size) {
			byteIndex = size - 1;
			columnInByte = 2;
		}

		int tokenIndex = byteIndex / byteGroupSize;
		int tokenOffset = (byteIndex % byteGroupSize) * 2 + columnInByte;

		// compensate for split group containing optional alignment bytes
		if (byteIndex >= size && residual != 0) {
			if ((byteIndex - size) < (byteGroupSize - residual)) {
				tokenOffset -= (residual * CHARS_IN_BYTE);
			}
			++tokenIndex;
		}

		ListingTextField btf = (ListingTextField) bf;
		RowColLocation rcl = btf.dataToScreenLocation(tokenIndex, tokenOffset);
		if (hasSamePath(bf, loc)) {
			return new FieldLocation(index, fieldNum, rcl.row(), rcl.col());
		}
		return null;
	}

	@Override
	public Color getDefaultColor() {
		return DEFAULT_COLOR;
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!CodeUnit.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA ||
			category == FieldFormatModel.OPEN_DATA);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider provider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new BytesFieldFactory(formatModel, provider, displayOptions, fieldOptions);
	}

}
