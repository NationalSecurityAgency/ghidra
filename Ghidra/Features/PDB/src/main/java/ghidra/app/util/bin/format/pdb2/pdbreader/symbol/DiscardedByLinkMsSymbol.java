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

import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents the Discarded By Link symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public class DiscardedByLinkMsSymbol extends AbstractMsSymbol {

	public static final int PDB_ID = 0x113b;

	public enum DiscardReason {

		INVALID("", -1),
		UNKNOWN("Unknown", 0),
		NOT_SELECTED("Not selected", 1),
		NOT_REFERENCED("Not referenced", 2);

		private static final Map<Integer, DiscardReason> BY_VALUE = new HashMap<>();
		static {
			for (DiscardReason val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static DiscardReason fromValue(int val) {
			return BY_VALUE.getOrDefault(val, INVALID);
		}

		private DiscardReason(String label, int value) {
			this.label = label;
			this.value = value;
		}
	}

	//==============================================================================================
	private int discardedVal;
	private DiscardReason discard;
	private long fileId;
	private long firstLineNumber;
	private List<AbstractMsSymbol> symbolList;

	//==============================================================================================
	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 * @throws CancelledException Upon user cancellation.
	 */
	public DiscardedByLinkMsSymbol(AbstractPdb pdb, PdbByteReader reader)
			throws PdbException, CancelledException {
		super(pdb, reader);
		long fields = reader.parseUnsignedIntVal();
		discardedVal = (int) (fields & 0xff);
		discard = DiscardReason.fromValue(discardedVal);
		fileId = reader.parseUnsignedIntVal();
		firstLineNumber = reader.parseUnsignedIntVal();
		byte[] data = reader.parseBytesRemaining();
		// This might be wrong, but I'm assuming that data contains a bunch of records that
		//  can be parsed.  MSFT API is hard to understand... it seems to be accessing global
		//  symbol information (GSI) hash records, which is different than what I'm coding here.
		// TODO: Need real data to evaluate.
		PdbByteReader dataReader = new PdbByteReader(data);
//		SymbolParser parser = new SymbolParser(pdb);
//		symbolList = parser.deserializeSymbolRecords(dataReader);
		symbolList = getOrderedSymbols(
			pdb.getSymbolRecords().deserializeSymbolRecords(dataReader, TaskMonitor.DUMMY));
	}

	/**
	 * Returns the list of symbols in the order they were seen.
	 * @return the list of symbols.
	 */
	private List<AbstractMsSymbol> getOrderedSymbols(Map<Long, AbstractMsSymbol> symbolsByOffset) {
		List<Long> offsets = new ArrayList<>(symbolsByOffset.keySet());
		List<AbstractMsSymbol> symbols = new ArrayList<>();
		for (long offset : offsets) {
			symbols.add(symbolsByOffset.get(offset));
		}
		return symbols;
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: ", getSymbolTypeName()));
		if (discard == DiscardReason.UNKNOWN) {
			builder.append(String.format("(%02X)", discardedVal));
		}
		else {
			builder.append(discard);
		}
		if (fileId != 0xffffffff) {
			builder.append(String.format(", FileId: %08X", fileId));
			// TODO: evaluate.  MSFT API has a whole bunch of stuff going on here; do not yet
			//  understand...
			builder.append(String.format(", Line: %8d", firstLineNumber));
		}
		builder.append("\n");
		for (AbstractMsSymbol symbol : symbolList) {
			builder.append(symbol);
			builder.append("\n");
		}
	}

	@Override
	protected String getSymbolTypeName() {
		return "DISCARDED";
	}

}
