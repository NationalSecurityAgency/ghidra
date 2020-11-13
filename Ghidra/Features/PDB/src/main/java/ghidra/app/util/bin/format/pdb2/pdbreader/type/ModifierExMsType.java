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
package ghidra.app.util.bin.format.pdb2.pdbreader.type;

import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * This class represents the <B>MsType</B> flavor of Extended Modifier type.
 * <P>
 * Note: we do not necessarily understand each of these data type classes.  Refer to the
 *  base class for more information.
 */
public class ModifierExMsType extends AbstractMsType {

	public static final int PDB_ID = 0x1518;

	public enum Modifier {

		INVALID("INVALID ", 0),
		CONST("const ", 1),
		VOLATILE("volatile ", 2),
		UNALIGNED("__unaligned ", 3),
		// HLSL modifiers 0x0200 - 0x03ff
		HLSL_UNIFORM("__uniform__ ", 0x0200),
		HLSL_LINE("__line__ ", 0x0201),
		HLSL_TRIANGLE("__triangle__ ", 0x0202),
		HLSL_LINEADJ("__lineadj__ ", 0x0203),
		HLSL_TRIANGLEADJ("__triangleadj__ ", 0x0204),
		HLSL_LINEAR("__linear__ ", 0x0205),
		HLSL_CENTROID("__centroid__ ", 0x0206),
		HLSL_CONSTINTERP("__constinterp__ ", 0x0207),
		HLSL_NOPERSPECTIVE("__noperspective__ ", 0x0208),
		HLSL_SAMPLE("__sample__ ", 0x0209),
		HLSL_CENTER("__center__ ", 0x020a),
		HLSL_SNORM("__snorm__ ", 0x020b),
		HLSL_UNORM("__unorm__ ", 0x020c),
		HLSL_PRECISE("__precise__ ", 0x020d),
		HLSL_UAV_GLOBALLY_COHERENT("__uav_globally_coherent__ ", 0x020e);

		private static final Map<Integer, Modifier> BY_VALUE = new HashMap<>();
		static {
			for (Modifier val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		/**
		 * Emits {@link String} output of this class into the provided {@link StringBuilder}.
		 * @param builder The {@link StringBuilder} into which the output is created.
		 */
		public void emit(StringBuilder builder) {
			builder.append(this.getClass().getSimpleName());
		}

		@Override
		public String toString() {
			return label;
		}

		public static Modifier fromValue(int val) {
			return BY_VALUE.getOrDefault(val, INVALID);
		}

		private Modifier(String label, int value) {
			this.label = label;
			this.value = value;
		}

	}

	//==============================================================================================
	private RecordNumber modifiedRecordNumber;
	//TODO: alternative to List, could create a bunch of booleans (e.g., isConst), and put
	// methods in place to test (e.g., public boolean isConst()).  Then emit() method would
	// have to put the modifier strings in a predesigned order instead of the order that they
	// were found in the record.
	private List<Modifier> modifiers = new ArrayList<>();

	//==============================================================================================
	/**
	 * Constructor for this type.
	 * @param pdb {@link AbstractPdb} to which this type belongs.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public ModifierExMsType(AbstractPdb pdb, PdbByteReader reader) throws PdbException {
		super(pdb, reader);
		modifiedRecordNumber = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32);
		int count = reader.parseUnsignedShortVal();
		for (int i = 0; i < count; i++) {
			// TODO: Not sure if these are unsigned short or int.
			Modifier modifier = Modifier.fromValue(reader.parseUnsignedShortVal());
			if (modifier == Modifier.INVALID) {
				// Should not happen, but could output a warning.
			}
			modifiers.add(modifier);
		}
	}

	@Override
	public int getPdbId() {
		return PDB_ID;
	}

	/**
	 * Tells whether the the {@link Modifier} is present.
	 * @param modifier the {@link Modifier} to check.
	 * @return True if the {@link Modifier} is present.
	 */
	public boolean hasModifier(Modifier modifier) {
		return modifiers.contains(modifier);
	}

	@Override
	public void emit(StringBuilder builder, Bind bind) {
		StringBuilder modBuilder = new StringBuilder();
		for (Modifier modifier : modifiers) {
			modBuilder.append(modifier);
		}
		modBuilder.append(pdb.getTypeRecord(modifiedRecordNumber));
		builder.insert(0, modBuilder);
	}

}
