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
 * This class represents the Frame Security Cookie symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class FrameSecurityCookieMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x113a;

	public enum CookieType {

		INVALID("invalid", -1),
		COPY("COPY", 0),
		XOR_SP("XOR_SP", 1),
		XOR_BP("XOR_BP", 2),
		XOR_R13("XOR_R13", 3);

		private static final Map<Integer, CookieType> BY_VALUE = new HashMap<>();
		static {
			for (CookieType val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static CookieType fromValue(int val) {
			return BY_VALUE.getOrDefault(val, INVALID);
		}

		private CookieType(String label, int value) {
			this.label = label;
			this.value = value;
		}
	}

	protected long offset;
	protected int registerIndex;
	protected RegisterName registerName;
	protected CookieType cookieType;
	protected int flags;

	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public FrameSecurityCookieMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		offset = reader.parseVarSizedOffset(32);
		registerIndex = reader.parseUnsignedShortVal();
		registerName = new RegisterName(pdb, registerIndex);
		// One example seems to show only room for a byte here, leaving the last byte for flags.
		cookieType = CookieType.fromValue(reader.parseUnsignedByteVal());
		flags = reader.parseUnsignedByteVal();
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Returns the offset.
	 * @return Offset.
	 */
	public long getOffset() {
		return offset;
	}

	/**
	 * Returns the register index.
	 * @return Register index.
	 */
	public int getRegisterIndex() {
		return registerIndex;
	}

	/**
	 * Returns the register name.
	 * @return Register name.
	 */
	public String getRegisterNameString() {
		return registerName.toString();
	}

	/**
	 * Returns the {@link CookieType}.
	 * @return Cookie type index.
	 */
	public CookieType getCookieType() {
		return cookieType;
	}

	/**
	 * Returns the flags.
	 * @return Flags.
	 */
	public int getFlags() {
		return flags;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: %s+%08X, Type: %s, %02X", getSymbolTypeName(),
			registerName.toString(), offset, cookieType.toString(), flags));
	}

	@Override
	protected String getSymbolTypeName() {
		return "FRAMECOOKIE";
	}

}
