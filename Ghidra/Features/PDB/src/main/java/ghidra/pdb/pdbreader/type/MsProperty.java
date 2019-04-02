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
package ghidra.pdb.pdbreader.type;

import ghidra.pdb.*;

/**
 * Property attributes used for various specific PDB data type.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 */
public class MsProperty extends AbstractParsableItem {

	public static final int HFA_NONE = 0;
	public static final int HFA_FLOAT = 1;
	public static final int HFA_DOUBLE = 2;
	public static final int HFA_RESV = 3;

	public static final int MOCOM_NONE = 0;
	public static final int MOCOM_REF = 1;
	public static final int MOCOM_VALUE = 2;
	public static final int MOCOM_INTERFACE = 3;

	private static final String[] HFA_STRING = new String[4];
	static {
		HFA_STRING[0] = "";
		HFA_STRING[1] = "hfaFloat";
		HFA_STRING[2] = "hfaDouble";
		HFA_STRING[3] = "hfa(3)";

	}
	private static final String[] MOCOM_STRING = new String[4];
	static {
		MOCOM_STRING[0] = "";
		MOCOM_STRING[1] = "ref";
		MOCOM_STRING[2] = "value";
		MOCOM_STRING[3] = "interface";

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

	private int hfaVal; // ???
	private int mocomVal; // ????

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

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isPacked() {
		return packedStructure;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean hasConstructorOrDestructor() {
		return constructorOrDestructorPresent;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean hasOverloadedOperators() {
		return overloadedOperatorsPresent;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isNestedClass() {
		return isNestedClass;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean containsNestedTypes() {
		return containsNestedTypes;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean hasOverloadedAssignment() {
		return hasOverloadedAssignment;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean hasCastingMethods() {
		return hasCastingMethods;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isForwardReference() {
		return isForwardReference;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean hasScopedDefinition() {
		return scopedDefinition;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean hasUniqueName() {
		return hasUniqueName;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean cannotBeBaseClass() {
		return sealed;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isIntrinsic() {
		return isIntrinsic;
	}

	/**
	 * Gets the value (index) of the property.
	 * @return The index value of the property.
	 */
	public int getHfaVal() {
		return hfaVal;
	}

	/**
	 * Gets the value (index) of the property.
	 * @return The index value of the property.
	 */
	public int getMocomVal() {
		return mocomVal;
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
		builder.append(ds.out((hfaVal != 0), HFA_STRING[hfaVal]));
		builder.append(ds.out(isIntrinsic, INTRINSIC_STRING));
		builder.append(ds.out((mocomVal != 0), MOCOM_STRING[mocomVal]));
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

		hfaVal = (properties & 0x0003);
		properties >>= 2;

		isIntrinsic = ((properties & 0x0001) == 0x0001);
		properties >>= 1;

		mocomVal = (properties & 0x0003);
	}

}
