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
import ghidra.pdb.pdbreader.*;

/**
 * This class represents various flavors of Thunk symbol.
 * <P>
 * Note: we do not necessarily understand each of these symbol type classes.  Refer to the
 *  base class for more information.
 */
public abstract class AbstractThunkMsSymbol extends AbstractMsSymbol {

	public enum Ordinal {

		NOTYPE("", 0),
		ADJUSTOR("Type: Adjustor", 1),
		VCALL("Type: VCall", 2),
		PCODE("Type: 03", 3),
		LOAD("Type: 04", 4),
		TRAMPOLINE_INCREMENTAL("Type: 05", 5),
		TRANMPOLINE_BRANCHISLAND("Type: 06", 6);

		private static final Map<Integer, Ordinal> BY_VALUE = new HashMap<>();
		static {
			for (Ordinal val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static Ordinal fromValue(int val) {
			return BY_VALUE.getOrDefault(val, NOTYPE);
		}

		private Ordinal(String label, int value) {
			this.label = label;
			this.value = value;
		}
	}

	//==============================================================================================
	protected long parentPointer;
	protected long endPointer;
	protected long nextPointer;
	protected AbstractOffset offset;
	protected int segment;
	protected int length;
	protected Ordinal ordinal;
	protected AbstractString name;
	protected int variant;
	protected AbstractString variantString;

	//==============================================================================================
	/**
	 * Constructor for this symbol.
	 * @param pdb {@link AbstractPdb} to which this symbol belongs.
	 * @param reader {@link PdbByteReader} from which this symbol is deserialized.
	 * @throws PdbException upon error parsing a field.
	 */
	public AbstractThunkMsSymbol(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		create();
		parentPointer = reader.parseUnsignedIntVal();
		endPointer = reader.parseUnsignedIntVal();
		nextPointer = reader.parseUnsignedIntVal();
		offset.parse(reader);
		segment = reader.parseUnsignedShortVal();
		length = reader.parseUnsignedShortVal();
		ordinal = Ordinal.fromValue(reader.parseUnsignedByteVal());
		name.parse(reader);
		switch (ordinal) {
			case ADJUSTOR:
				variant = reader.parseUnsignedShortVal();
				variantString.parse(reader);
				break;
			case VCALL:
				variant = reader.parseUnsignedShortVal();
				break;
			default:
				variant = 0;
				break;
		}
		reader.align4();
	}

	/**
	 * Returns the parent pointer.
	 * @return Parent pointer.
	 */
	public long getParentPointer() {
		return parentPointer;
	}

	/**
	 * Returns the end pointer.
	 * @return End pointer.
	 */
	public long getEndPointer() {
		return endPointer;
	}

	/**
	 * Returns the next pointer
	 * @return Next pointer.
	 */
	public long getNextPointer() {
		return nextPointer;
	}

	/**
	 * Returns the offset.
	 * @return Offset.
	 */
	public long getOffset() {
		return offset.get();
	}

	/**
	 * Returns the segment.
	 * @return Segment.
	 */
	public int getSegment() {
		return segment;
	}

	/**
	 * Returns the length.
	 * @return Length.
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Returns the {@link Ordinal}.
	 * @return {@link Ordinal}.
	 */
	public Ordinal getOrdinal() {
		return ordinal;
	}

	/**
	 * Returns the name.
	 * @return Name.
	 */
	public String getName() {
		return name.get();
	}

	/**
	 * Returns the variant.
	 * @return Variant.
	 */
	public int getVariant() {
		return variant;
	}

	public String getVariantString() {
		if (ordinal == Ordinal.ADJUSTOR) {
			return variantString.get();
		}
		return "";
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(String.format("%s: [%04X:%08X], Length: %08X, %s\n", getSymbolTypeName(),
			segment, offset.get(), length, name.get()));
		builder.append(String.format("   Parent: %08X, End: %08X, Next: %08X\n", parentPointer,
			endPointer, nextPointer));
		switch (ordinal) {
			case NOTYPE:
				break;
			case ADJUSTOR:
				builder.append(String.format("   " + ordinal + ", Delta: %d, Target: %s\n", variant,
					variantString.get()));
				break;
			case VCALL:
				builder.append(String.format("   " + ordinal + ", Table Entry: %d\n", variant));
				break;
			default:
				builder.append("   " + ordinal + "\n");
				break;
		}
	}

	/**
	 * Creates subcomponents for this class, which can be deserialized later.
	 * <P>
	 * Implementing class must initialize {@link #offset}, {@link #name}, and
	 * {@link #variantString}.
	 */
	protected abstract void create();

}
