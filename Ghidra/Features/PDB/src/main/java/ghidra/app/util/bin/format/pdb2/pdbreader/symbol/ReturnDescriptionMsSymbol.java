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
package ghidra.app.util.bin.format.pdb2.pdbreader.symbol;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents the Return Description symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class ReturnDescriptionMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x000d;

	public enum Style {

		UNKNOWN("unknown return", -1),
		VOID("void return", 0x00),
		RETURN_DATA_IN_REGISTERS("return data in registers", 0x01),
		INDIRECT_CALLER_ALLOCATED_NEAR("indirected caller-allocated near", 0x02),
		INDIRECT_CALLER_ALLOCATED_FAR("indirect caller-allocated far", 0x03),
		INDIRECT_RETURNEE_ALLOCATED_NEAR("indirect returnee allocated near", 0x04),
		INDIRECT_RETURNEE_ALLOCATED_FAR("indirect returnee allocated far", 0x05),
		UNUSED("unused", 0x06);

		private static final Map<Integer, Style> BY_VALUE = new HashMap<>();
		static {
			for (Style val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static Style fromValue(int val) {
			return BY_VALUE.getOrDefault(val, UNKNOWN);
		}

		private Style(String label, int value) {
			this.label = label;
			this.value = value;
		}
	}

	//==============================================================================================
	private boolean varargsPushedRightToLeft;
	private boolean returneeCleansUpStack;
	private Style style;
	private int bytesRemaining;

	//==============================================================================================
	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public ReturnDescriptionMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		int flags = reader.parseUnsignedShortVal();
		processFlags(flags);
		style = Style.fromValue(reader.parseUnsignedByteVal());
		// Don't know what the format is of remaining data.
		bytesRemaining = reader.getLimit() - reader.getIndex();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the {@link Style} of return.
	 * @return The {@link Style} of return
	 */
	public Style getStyle() {
		return style;
	}

	/**
	 * Tells whether the varargs are pushed right-to-left.
	 * @return True if varargs were pushed right-to-left.
	 */
	public boolean isVarargsPushedRightToLeft() {
		return varargsPushedRightToLeft;
	}

	/**
	 * Tells whether the returnee is responsible for cleaning up the stack.
	 * @return TruE if the returnee is responsible for cleaning up the stack.
	 */
	public boolean isReturneeCleansUpStack() {
		return returneeCleansUpStack;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s, ", getSymbolTypeName()));
		builder.append(style);
		builder.append(
			varargsPushedRightToLeft ? ", varargs right-to-left" : ", varargs left-to-right");
		builder.append(returneeCleansUpStack ? ", returnee cleans stack" : ", caller cleans stack");
		builder.append(
			String.format("; byte length of remaining method data = %d", bytesRemaining));
	}

	@Override
	protected String getSymbolTypeName() {
		return "RETURN";
	}

	private void processFlags(int val) {
		varargsPushedRightToLeft = ((val & 0x0001) == 0x0001);
		val >>= 1;
		returneeCleansUpStack = ((val & 0x0001) == 0x0001);
	}

}
