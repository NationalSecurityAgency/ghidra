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
import ghidra.program.model.mem.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HTMLUtilities;

/**
 * A hover service to show tool tip text for hovering over scalar values.
 * The tooltip shows the scalar in different bases.
 */
public abstract class AbstractScalarOperandHover extends AbstractConfigurableHover {

	private static final FormatSettingsDefinition FORMAT = FormatSettingsDefinition.DEF;

	//@formatter:off
	private static final Settings[] INTEGER_SETTINGS = new Settings[] { 
		getSettingsForRadix("hex"),
		getSettingsForRadix("decimal"), 
		getSettingsForRadix("char")
	};

	private static final AbstractIntegerDataType[] DISPLAY_TYPES =
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

	protected String formatScalar(Program program, Address addr, Scalar scalar) {

		StringBuilder sb = new StringBuilder(HTMLUtilities.HTML);

		byte[] opBytes = getOperandBytes(scalar);
		int opSize = opBytes.length;

		Memory memory = program.getMemory();
		MemBuffer memBuffer = new ByteMemBufferImpl(addr, opBytes, !memory.isBigEndian());

		buildTableHeader(sb);

		// For each data type, render different the bases/formats
		for (DataType type : DISPLAY_TYPES) {

			if (type.getLength() != opSize) {
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

		sb.append("</table>");

		// maybe the scalar is an address..
		long scalarLong = scalar.getValue();
		AddressFactory factory = program.getAddressFactory();
		AddressSpace space = factory.getDefaultAddressSpace();
		Address asAddress;
		try {
			asAddress = factory.getAddress(space.getBaseSpaceID(), scalarLong);
		}
		catch (AddressOutOfBoundsException ex) {
			asAddress = null;	// Constant doesn't make sense as an address
		}
		if (asAddress != null && memory.contains(asAddress)) {
			sb.append("<hr>");
			sb.append("<table>");

			addReprRow(sb, "Address", asAddress.toString());

			// .. and maybe it points to some data...
			Data data = program.getListing().getDataContaining(asAddress);
			if (data != null) {
				Symbol primary = data.getPrimarySymbol();
				if (primary != null) {
					addReprRow(sb, "Symbol", HTMLUtilities.italic(primary.getName()));

				}
			}

			sb.append("</table>");
		}

		return sb.toString();
	}

	private byte[] getOperandBytes(Scalar scalar) {
		byte[] operandBytes = scalar.byteArrayValue();
		byte[] trimmed = trimLeadingZeros(operandBytes);
		return trimmed;
	}

	private static byte[] trimLeadingZeros(byte[] bytes) {
		int fullLength = bytes.length;
		for (int i = 0; i < fullLength; i++) {
			if (bytes[i] == 0) {
				continue;
			}

			if (i == 0) {
				// non-zero value in the first byte--nothing to trim
				break;
			}

			int toCopy = fullLength - i;
			int len = toCopy;
			if (len < 2) {
				len = 2;
			}
			else if (len < 4) {
				len = 4;
			}
			else if (len < 8) {
				len = 8;
			}

			byte[] newBytes = new byte[len];
			int offset = len - toCopy;
			System.arraycopy(bytes, i, newBytes, offset, toCopy);
			return newBytes;
		}
		return bytes;
	}

	private static void buildTableHeader(StringBuilder sb) {
		sb.append("<table><tr><th></th>");
		for (Settings setting : INTEGER_SETTINGS) {

			String radixName = FORMAT.getDisplayChoice(setting);
			radixName = Character.toTitleCase(radixName.charAt(0)) + radixName.substring(1);

			sb.append("<th>").append(radixName).append("</th>");
		}
		sb.append("</tr>");
	}

	private static void addReprRow(StringBuilder sb, String typeName, String repr) {
		addReprRow(sb, typeName, Arrays.asList(new String[] { repr }));
	}

	private static void addReprRow(StringBuilder sb, String typeName, Iterable<String> reprs) {
		sb.append("<tr><td style=\"text-align: left;\">").append(typeName).append("</td>");
		for (String repr : reprs) {
			sb.append("<td style=\"text-align: right;\">").append(repr).append("</td>");
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
