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
package ghidra.pdb.pdbreader.symbol;

import java.util.HashMap;
import java.util.Map;

import ghidra.pdb.PdbByteReader;
import ghidra.pdb.PdbException;
import ghidra.pdb.pdbreader.AbstractOffset;
import ghidra.pdb.pdbreader.AbstractPdb;

/**
 * This class represents various flavors of Change Execution Model symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractChangeExecutionModelMsSymbol extends AbstractMsSymbol {

	public enum Model {

		TABLE("DATA", 0x00),
		JUMPTABLE("JUMPTABLE", 0x01),
		DATAPAD("DATAPAD", 0x02),
		NATIVE("NATIVE", 0x20),
		COBOL("COBOL", 0x21),
		CODEPAD("CODEPAD", 0x22),
		CODE("CODE", 0x23),
		SQL("SQL", 0x30),
		PCODE("PCODE", 0x40),
		PCODE32MACINTOSH("PCODE for the Mac", 0x41),
		PCODE32MACINTOSH_NATIVE_ENTRY_POINT("PCODE for the Mac (Native Entry Point)", 0x42),
		JAVAINT("JAVAINT", 0x50),
		UNKNOWN("UNKNOWN MODEL", 0Xff);

		private static final Map<Integer, Model> BY_VALUE = new HashMap<>();
		static {
			for (Model val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static Model fromValue(int val) {
			return BY_VALUE.getOrDefault(val, UNKNOWN);
		}

		private Model(String label, int value) {
			this.label = label;
			this.value = value;
		}
	}

	//==============================================================================================
	protected AbstractOffset offset;
	protected int segment;
	protected int modelVal;
	protected Model model;
	// For pcode:
	protected long offsetToPcodeFunctionTable;
	protected long offsetToSegmentPcodeInformation;
	// For cobol:
	protected int subtype; // subtype (API: values are missing)
	protected int flag;

	//==============================================================================================
	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public AbstractChangeExecutionModelMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException {
		super(pdb, reader);
		create();
		offset.parse(reader);
		segment = reader.parseUnsignedShortVal();
		modelVal = reader.parseUnsignedShortVal();
		model = Model.fromValue(modelVal);
		parseSpecifics(reader);
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s:\n   segment, offset = %04X:%08X, model = ",
			getSymbolTypeName(), segment, offset.get()));
		if (emitAdditionalModelCases(builder)) {
			return;
		}
		builder.append(model);
		if (model == Model.COBOL) {
			builder.append("\n");
			switch (subtype) {
				case 0x00:
					builder.append("   don't stop until next execution model\n");
					break;
				case 0x01:
					builder.append("   inter-segment perform - treat as single call instruction\n");
					break;
				case 0x02:
					builder.append("   false call - step into even with F10\n");
					break;
				case 0x03:
					builder.append(
						String.format("   call to EXTCALL - step into %d call levels\n", flag));
					break;
				default:
					builder.append(String.format("   UNKNOWN COBOL CONTROL 0x%04X\n", subtype));
					break;
			}
		}
		else if (model == Model.PCODE) {
			builder.append("\n");
			builder.append(String.format(
				"offsetToPcodeFunctionTable = %08X, offsetToSegmentPcodeInformation = %08X\n",
				offsetToPcodeFunctionTable, offsetToSegmentPcodeInformation));
		}
		else if (model == Model.UNKNOWN) {
			builder.append(String.format(" = %04X\n", modelVal));
		}
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #offset}.
	 */
	protected abstract void create();

	/**
	 * Parses some specific values for this version of symbol.
	 * <P>
	 * Implementing class must, in the appropriate order pertinent to itself, do the following:
	 * <PRE>
	 * if {@link #model}=={@link #AbstractChangeExecutionModelMsSymbol.Model.COBOL}, then parse
	 *    {@link #subtype} and {@link #flag}
	 * else if {@link #model}=={@link #AbstractChangeExecutionModelMsSymbol.Model.PCODE}, then parse
	 *    {@link #offsetToPcodeFunctionTable} and {@link #offsetToSegmentPcodeInformation}. </PRE>
	 * @param reader {@link PdbByteReader} from which to parse the information.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseSpecifics(PdbByteReader reader) throws PdbException;

	/**
	 * Emits additional model cases for the parser.
	 * @param builder {@link StringBuilder} to which the information is emitted.
	 * @return True if found a known case.
	 */
	protected abstract boolean emitAdditionalModelCases(StringBuilder builder);

}
