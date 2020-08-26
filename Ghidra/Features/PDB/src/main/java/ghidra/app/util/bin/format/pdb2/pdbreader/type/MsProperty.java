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

import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;

/**
 * Property attributes used for various specific PDB data type.
 */
public class MsProperty extends AbstractParsableItem {

	public static final MsProperty NONE = new MsProperty(false);

	public enum Hfa {

		@SuppressWarnings("hiding") // for NONE
		NONE("", 0), FLOAT("hfaFloat", 1), DOUBLE("hfaDouble", 2), RESV("hfa(3)", 3);

		private static final Map<Integer, Hfa> BY_VALUE = new HashMap<>();
		static {
			for (Hfa val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static Hfa fromValue(int val) {
			return BY_VALUE.getOrDefault(val, NONE);
		}

		private Hfa(String label, int value) {
			this.label = label;
			this.value = value;
		}
	}

	public enum Mocom {

		@SuppressWarnings("hiding") // for NONE
		NONE("", 0), REF("ref", 1), VALUE("value", 2), INTERFACE("interface", 3);

		private static final Map<Integer, Mocom> BY_VALUE = new HashMap<>();
		static {
			for (Mocom val : values()) {
				BY_VALUE.put(val.value, val);
			}
		}

		public final String label;
		public final int value;

		@Override
		public String toString() {
			return label;
		}

		public static Mocom fromValue(int val) {
			return BY_VALUE.getOrDefault(val, NONE);
		}

		private Mocom(String label, int value) {
			this.label = label;
			this.value = value;
		}
	}

	private static final String PACKED_STRING = "packed";
	private static final String CTOR_STRING = "ctor";
	private static final String OVERLOADED_OPS_STRING = "ovlops";
	private static final String NESTED_STRING = "isnested";
	private static final String CONTAINS_NESTED_STRING = "cnested";
	private static final String OVERLOADED_ASSIGN_STRING = "opassign";
	private static final String CASTING_METHODS_STRING = "opcast";
	private static final String FORWARD_REFS_STRING = "fwdref";
	private static final String SCOPED_STRING = "scoped";
	private static final String HAS_UNIQUE_NAME_STRING = "hasuniquename";
	private static final String SEALED_STRING = "sealed";
	private static final String INTRINSIC_STRING = "intrinsic";

	//==============================================================================================
	private boolean packedStructure;
	private boolean constructorOrDestructorPresent;
	private boolean overloadedOperatorsPresent;
	private boolean isNestedClass;
	private boolean containsNestedTypes;
	private boolean hasOverloadedAssignment;
	private boolean hasCastingMethods;
	private boolean isForwardReference;
	private boolean scopedDefinition;
	private boolean hasUniqueName; // A decorated name that follows the regular name
	private boolean sealed; // Cannot be used as a base class
	private boolean isIntrinsic; // (e.g., _m128d)

	private Hfa hfa; // ???
	private Mocom mocom; // ????

	//==============================================================================================
	/**
	 * Constructor for MsProperty.
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public MsProperty(PdbByteReader reader) throws PdbException {
		int properties = reader.parseUnsignedShortVal();
		processProperties(properties);
	}

	private MsProperty(boolean isFwdRef) {
		this.isForwardReference = isFwdRef;
		this.hfa = Hfa.NONE;
		this.mocom = Mocom.NONE;
	}

	/**
	 * Tells whether the structure is packed.
	 * @return True if structure is packed.
	 */
	public boolean isPacked() {
		return packedStructure;
	}

	/**
	 * Tells whether a constructor or destructor is present.
	 * @return True if a constructor or destructor is present.
	 */
	public boolean hasConstructorOrDestructor() {
		return constructorOrDestructorPresent;
	}

	/**
	 * Tells whether there are overloaded operators.
	 * @return True if there are overloaded operators.
	 */
	public boolean hasOverloadedOperators() {
		return overloadedOperatorsPresent;
	}

	/**
	 * Tells whether the class is a nested class.
	 * @return True if the class is a nested class.
	 */
	public boolean isNestedClass() {
		return isNestedClass;
	}

	/**
	 * Tells whether there are contained nested types.
	 * @return True if there are nested types.
	 */
	public boolean containsNestedTypes() {
		return containsNestedTypes;
	}

	/**
	 * Tells whether there is an overloaded assignment.
	 * @return True if there is an overloaded assignment.
	 */
	public boolean hasOverloadedAssignment() {
		return hasOverloadedAssignment;
	}

	/**
	 * Tells whether there are casting methods.
	 * @return True if there are casting methods.
	 */
	public boolean hasCastingMethods() {
		return hasCastingMethods;
	}

	/**
	 * Tells whether it is a forward reference.
	 * @return True if it is a forward reference.
	 */
	public boolean isForwardReference() {
		return isForwardReference;
	}

	/**
	 * Tells whether the the definition is scoped.
	 * @return True if there definition is scoped.
	 */
	public boolean hasScopedDefinition() {
		return scopedDefinition;
	}

	/**
	 * Tells if it has a unique name.
	 * @return True if it has a unique name.
	 */
	public boolean hasUniqueName() {
		return hasUniqueName;
	}

	/**
	 * Tells whether it can be a base class
	 * @return True if it can be a base class.
	 */
	public boolean isSealed() {
		return sealed;
	}

	/**
	 * Tells whether it is intrinsic.
	 * @return True if it is intrinsic.
	 */
	public boolean isIntrinsic() {
		return isIntrinsic;
	}

	/**
	 * Gets the {@link Hfa} kind.
	 * @return The {@link Hfa} kind.
	 */
	public Hfa getHfa() {
		return hfa;
	}

	/**
	 * Gets the {@link Mocom} kind.
	 * @return The {@link Mocom} kind.
	 */
	public Mocom getMocom() {
		return mocom;
	}

	@Override
	public void emit(StringBuilder builder) {
		DelimiterState ds = new DelimiterState("", " ");
		builder.append(ds.out(packedStructure, PACKED_STRING));
		builder.append(ds.out(constructorOrDestructorPresent, CTOR_STRING));
		builder.append(ds.out(overloadedOperatorsPresent, OVERLOADED_OPS_STRING));
		builder.append(ds.out(isNestedClass, NESTED_STRING));
		builder.append(ds.out(containsNestedTypes, CONTAINS_NESTED_STRING));
		builder.append(ds.out(hasOverloadedAssignment, OVERLOADED_ASSIGN_STRING));
		builder.append(ds.out(hasCastingMethods, CASTING_METHODS_STRING));
		builder.append(ds.out(isForwardReference, FORWARD_REFS_STRING));
		builder.append(ds.out(scopedDefinition, SCOPED_STRING));
		builder.append(ds.out(hasUniqueName, HAS_UNIQUE_NAME_STRING));
		builder.append(ds.out(sealed, SEALED_STRING));
		builder.append(ds.out((hfa != Hfa.NONE), hfa));
		builder.append(ds.out(isIntrinsic, INTRINSIC_STRING));
		builder.append(ds.out((mocom != Mocom.NONE), mocom));
	}

	private void processProperties(int properties) {
		packedStructure = ((properties & 0x0001) == 0x0001);
		properties >>= 1;
		constructorOrDestructorPresent = ((properties & 0x0001) == 0x0001);
		properties >>= 1;
		overloadedOperatorsPresent = ((properties & 0x0001) == 0x0001);
		properties >>= 1;
		isNestedClass = ((properties & 0x0001) == 0x0001);
		properties >>= 1;
		containsNestedTypes = ((properties & 0x0001) == 0x0001);
		properties >>= 1;
		hasOverloadedAssignment = ((properties & 0x0001) == 0x0001);
		properties >>= 1;
		hasCastingMethods = ((properties & 0x0001) == 0x0001);
		properties >>= 1;
		isForwardReference = ((properties & 0x0001) == 0x0001);
		properties >>= 1;
		scopedDefinition = ((properties & 0x0001) == 0x0001);
		properties >>= 1;
		hasUniqueName = ((properties & 0x0001) == 0x0001);
		properties >>= 1;
		sealed = ((properties & 0x0001) == 0x0001);
		properties >>= 1;

		hfa = Hfa.fromValue(properties & 0x0003);
		properties >>= 2;

		isIntrinsic = ((properties & 0x0001) == 0x0001);
		properties >>= 1;

		mocom = Mocom.fromValue(properties & 0x0003);
	}

}
