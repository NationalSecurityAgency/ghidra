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
package ghidra.app.plugin.core.hover;

import java.util.*;

import ghidra.docking.settings.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HTMLUtilities;
import ghidra.util.StringUtilities;

/**
 * A hover service to show tool tip text for hovering over scalar values.
 * The tooltip shows the scalar in different bases.
 */
public abstract class AbstractScalarOperandHover extends AbstractConfigurableHover {

	private static final FormatSettingsDefinition FORMAT = FormatSettingsDefinition.DEF;

	//@formatter:off
	private static final Settings[] INTEGER_SETTINGS = new Settings[] { 
		getSettingsForRadix("hex"),
		getSettingsForRadix("decimal") 
	};

	private static final AbstractIntegerDataType[] INTEGER_DISPLAY_TYPES =
		new AbstractIntegerDataType[] { 
			new ByteDataType(),
			new WordDataType(), 
			new SignedWordDataType(),
			new DWordDataType(), 
			new SignedDWordDataType(),
			new QWordDataType(), 
			new SignedQWordDataType()
		};
	//@formatter:on

	private static Settings getSettingsForRadix(String radix) {
		Settings s = new SettingsImpl();
		FORMAT.setDisplayChoice(s, radix);
		return s;
	}

	public AbstractScalarOperandHover(PluginTool tool, int priority) {
		super(tool, priority);
	}

	private void formatIntegerTypes(Program program, Address addr, Scalar scalar,
			StringBuilder htmlText) {
		ByteMemBufferImpl memBuffer = getScalarOperandAsMemBuffer(addr, scalar, 1);

		StringBuilder sb = new StringBuilder();

		// For each data type, render different the bases/formats
		for (DataType type : INTEGER_DISPLAY_TYPES) {

			if (type.getLength() != memBuffer.getLength()) {
				continue;
			}

			List<String> reprs = new ArrayList<>();
			for (Settings setting : INTEGER_SETTINGS) {
				String repr = type.getRepresentation(memBuffer, setting, type.getLength());
				if (repr.equals("??")) {
					repr = HTMLUtilities.HTML_SPACE;
				}
				reprs.add(repr);

			}
			addReprRow(sb, type.getDisplayName(), reprs);
		}

		if (sb.length() > 0) {
			htmlText.append("<table><tr><th nowrap>&nbsp;</th>");
			for (Settings setting : INTEGER_SETTINGS) {

				String radixName = FORMAT.getDisplayChoice(setting);
				radixName = Character.toTitleCase(radixName.charAt(0)) + radixName.substring(1);

				htmlText.append("<th nowrap>").append(radixName).append("</th>");
			}
			htmlText.append("</tr>");
			htmlText.append(sb);
			htmlText.append("</table>");
		}
	}

	private void formatCharTypes(Program program, Address addr, Scalar scalar,
			StringBuilder htmlText) {

		// The CharDataType can change depending on the DataOrg of the current program, so this
		// can't be a static array like INTEGER_DISPLAY_TYPES
		List<DataType> charDataTypes = Arrays.asList(new CharDataType(program.getDataTypeManager()),
			new WideChar16DataType(program.getDataTypeManager()),
			new WideChar32DataType(program.getDataTypeManager()));

		String prevCharVal = "";
		StringBuilder localHTMLText = new StringBuilder();

//		Endian progEndian = program.getMemory().isBigEndian() ? Endian.BIG : Endian.LITTLE;
		for (DataType charDt : charDataTypes) {
			// for each char data type, append its representation to the buffer, if it is
			// a new way to display the scalar
			ByteMemBufferImpl charMemBuffer =
				getScalarOperandAsMemBuffer(addr, scalar, charDt.getLength());
			prevCharVal =
				appendCharDataTypeFormattedHTML(prevCharVal, charDt, charMemBuffer, localHTMLText);
		}

		if (localHTMLText.length() > 0) {
			htmlText.append("<hr>");
			htmlText.append("<table width=\"100%\">") //
					.append(localHTMLText) //
					.append("</table>");
		}
	}

	private String appendCharDataTypeFormattedHTML(String prevCharVal, DataType charDt,
			ByteMemBufferImpl charMemBuffer, StringBuilder htmlText) {
		// appends a HTML table row to the string builder with the scalar displayed as the
		// specified data type, only if its a value that hasn't already been added to the buffer.

		if (charMemBuffer.getLength() >= charDt.getLength()) {
			StringDataInstance sdi = StringDataInstance.getStringDataInstance(charDt, charMemBuffer,
				SettingsImpl.NO_SETTINGS, charMemBuffer.getLength());
			boolean isArray = (charMemBuffer.getLength() >= charDt.getLength() * 2);
			String charVal = sdi.getStringValue();
			String charRep = isArray ? sdi.getStringRepresentation() : sdi.getCharRepresentation();

			// if the string-ified char data is the same as the previous instance, or if it
			// doesn't have a quote mark in it (ie. all bytes sequences), skip it
			boolean shouldSkip = prevCharVal.equals(charVal)  // 
				|| !charRep.contains(isArray ? "\"" : "'") //
				|| hasEncodingError(charVal);
			if (!shouldSkip) {
				htmlText.append("<tr><td>") // 
						.append(charDt.getName()) //
						.append(isArray ? "[]" : "");
				htmlText.append("</td><td>") //
						.append(HTMLUtilities.friendlyEncodeHTML(charRep)) //
						.append("</td></tr>");
				prevCharVal = charVal;
			}
		}
		return prevCharVal;
	}

	private void formatAsAddressVal(Program program, Address addr, Scalar scalar,
			StringBuilder htmlText) {

		// maybe the scalar is an address..
		long scalarLong = scalar.getValue();
		AddressFactory factory = program.getAddressFactory();
		AddressSpace space = factory.getDefaultAddressSpace();
		Address asAddress;
		try {
			asAddress = factory.getAddress(space.getSpaceID(), scalarLong);
		}
		catch (AddressOutOfBoundsException ex) {
			asAddress = null;	// Constant doesn't make sense as an address
		}

		Memory memory = program.getMemory();
		if (asAddress != null && memory.contains(asAddress)) {
			htmlText.append("<hr>");
			htmlText.append("<table>");

			addReprRow(htmlText, "Address", asAddress.toString());

			// .. and maybe it points to some data...
			Data data = program.getListing().getDataContaining(asAddress);
			if (data != null) {
				Symbol primary = data.getPrimarySymbol();
				if (primary != null) {
					addReprRow(htmlText, "Symbol",
						HTMLUtilities.italic(HTMLUtilities.friendlyEncodeHTML(primary.getName())));
				}
			}

			htmlText.append("</table>");
		}
	}

	protected String formatScalar(Program program, Address addr, Scalar scalar) {

		StringBuilder sb = new StringBuilder(HTMLUtilities.HTML);
		formatIntegerTypes(program, addr, scalar, sb);
		formatCharTypes(program, addr, scalar, sb);
		formatAsAddressVal(program, addr, scalar, sb);

		return sb.toString();
	}

	private boolean hasEncodingError(String s) {
		return s.codePoints()
				.anyMatch(
					codePoint -> codePoint == StringUtilities.UNICODE_REPLACEMENT);
	}

	private ByteMemBufferImpl getScalarOperandAsMemBuffer(Address addr, Scalar scalar,
			int minTrimLen) {
		byte[] operandBytes = scalar.byteArrayValue();
		if (minTrimLen > 0) {
			operandBytes = trimLeadingZeros(operandBytes, minTrimLen);
		}
		return new ByteMemBufferImpl(addr, operandBytes, true);
	}

	private static byte[] trimLeadingZeros(byte[] bytes, int minTrimLen) {
		int firstUsedByteIndex = 0;
		for (; firstUsedByteIndex < bytes.length &&
			bytes[firstUsedByteIndex] == 0; firstUsedByteIndex++) {
			// no op
		}

		int bytesToCopy = bytes.length - firstUsedByteIndex;
		int newLen = Math.max(bytesToCopy, minTrimLen);
		if (newLen > 1) {
			newLen += (newLen % 2);
		}
		byte[] newBytes = new byte[newLen];
		System.arraycopy(bytes, firstUsedByteIndex, newBytes, newLen - bytesToCopy, bytesToCopy);

		return newBytes;
	}

	private static void addReprRow(StringBuilder sb, String typeName, String repr) {
		addReprRow(sb, typeName, Arrays.asList(new String[] { repr }));
	}

	private static void addReprRow(StringBuilder sb, String typeName, Iterable<String> reprs) {
		sb.append("<tr><td nowrap style=\"text-align: left;\">").append(typeName).append("</td>");
		for (String repr : reprs) {
			sb.append("<td nowrap style=\"text-align: right;\">").append(repr).append("</td>");
		}
		sb.append("</tr>");
	}

	@Override
	protected boolean isValidTooltipContent(String content) {
		if (content == null || content.length() < HTMLUtilities.HTML.length()) {
			return false;
		}
		return true;
	}

}
