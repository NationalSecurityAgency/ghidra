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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;

abstract public class RecordNumber {

	public static final int T_NOTYPE = 0; // TODO: consider T_NOTYPE constant elsewhere
	public static final int T_VOID = 3; // TODO: consider T_VOID constant elsewhere

	public static final RecordNumber NO_TYPE = new TypeRecordNumber(T_NOTYPE);

	public static RecordNumber typeRecordNumber(int number) {
		if (number == T_NOTYPE) {
			return NO_TYPE;
		}
		return new TypeRecordNumber(number);
	}

	public static RecordNumber itemRecordNumber(int number) {
		if (number == T_NOTYPE) {
			return NO_TYPE;
		}
		return new ItemRecordNumber(number);
	}

// TODO: for consideration... has implications... SymbolGroup iterator vs. RecordNumber
//	public static RecordNumber symbolRecordNumber(int number) {
//		return new SymbolRecordNumber(number);
//	}

	public static RecordNumber make(RecordCategory cat, int number) {
		switch (cat) {
			case TYPE:
				return typeRecordNumber(number);
			case ITEM:
				return itemRecordNumber(number);
// TODO: for consideration... has implications... SymbolGroup iterator vs. RecordNumber
//			case SYMBOL:
//				return symbolRecordNumber(number);
			default:
				throw new IllegalArgumentException();
		}
	}

	public static RecordNumber parse(AbstractPdb pdb, PdbByteReader reader, RecordCategory category,
			int size) throws PdbException {
		int number = reader.parseVarSizedInt(size);
		RecordNumber recordNumber = make(category, number);
		pdb.getPdbReaderMetrics().witnessRecordNumber(recordNumber);
		return recordNumber;
	}

	// TODO: figure out the issues stated here... and revert to parse() method.
	/**
	 * Returns the record number without metrics detection.
	 * <P>
	 * This may be a temporary method...(should just use
	 * {@link #parse(AbstractPdb, PdbByteReader, RecordCategory, int)}.  Both
	 * {@link IndirectCallSiteInfoMsSymbol} and {@link InlinedFunctionCallsiteMsSymbol} seem to
	 * have issues.  The former has high bit set for TYPE, and the latter for ITEM, but after
	 * "fixing" them (masking and referring to opposite ITEM/TYPE), there still seems to be issues.
	 * TYPE->ITEM still ends up with a number less than min (4096), indicating a primitive (but
	 * then why not just use the standard "TYPE").  ITEM->TYPE is giving what seems to be too many
	 * unknown primitives.  I do not trust either of these.  The API indicates:
	 * {@code  CV_typ_t        typind;             // type index describing function signature} for
	 * {@link IndirectCallSiteInfoMsSymbol} and 
	 * {@code CV_ItemId       inlinee;   // CV_ItemId of inlinee} for
	 * {@link InlinedFunctionCallsiteMsSymbol}.
	 * <P>
	 * Similar for {@link AbstractFunctionListMsSymbol}
	 * <P>
	 * Other symbols might have issues as well.
	 * @param pdb {@link AbstractPdb} for which we are parsing
	 * @param reader {@link PdbByteReader} from which to deserialize the data
	 * @param category The catogory of record number
	 * @param size the field size to parse for the number
	 * @return the record number
	 * @throws PdbException upon issues parsing number field
	 */
	public static RecordNumber parseNoWitness(AbstractPdb pdb, PdbByteReader reader,
			RecordCategory category, int size) throws PdbException {
		int number = reader.parseVarSizedInt(size);
		RecordNumber recordNumber = make(category, number);
		return recordNumber;
	}

	private final int number;

	protected RecordNumber(int number) {
		this.number = number;
	}

	public abstract RecordCategory getCategory();

	public int getNumber() {
		return number;
	}

	public boolean isNoType() {
		return number == T_NOTYPE;
	}

	@Override
	public String toString() {
		return String.format("%s[%d]", getCategory().name(), getNumber());
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + number;
		result = prime * result + getCategory().hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		RecordNumber other = (RecordNumber) obj;
		if (number != other.number || getCategory() != other.getCategory()) {
			return false;
		}
		return true;
	}

//--------------------------------------------------------------------------------------------------

	private static class TypeRecordNumber extends RecordNumber {
		public TypeRecordNumber(int number) {
			super(number);
		}

		@Override
		public RecordCategory getCategory() {
			return RecordCategory.TYPE;
		}
	}

	private static class ItemRecordNumber extends RecordNumber {
		public ItemRecordNumber(int number) {
			super(number);
		}

		@Override
		public RecordCategory getCategory() {
			return RecordCategory.ITEM;
		}
	}

// TODO: for consideration... has implications... SymbolGroup iterator vs. RecordNumber
//	private static class SymbolRecordNumber extends RecordNumber {
//		public SymbolRecordNumber(int number) {
//			super(number);
//		}
//
//		@Override
//		public RecordCategory getCategory() {
//			return RecordCategory.SYMBOL;
//		}
//	}
//
}
