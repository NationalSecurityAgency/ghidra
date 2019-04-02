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
 * Class field attributes used on fields within specific PDB data type.
 * <P>
 * For more information about PDBs, consult the Microsoft PDB API, see
 * <a href="https://devblogs.microsoft.com/cppblog/whats-inside-a-pdb-file">
 * What's inside a PDB File</a>.
 */
public class ClassFieldMsAttributes extends AbstractParsableItem {

	private static final int ACCESS_BLANK = 0;
	private static final int ACCESS_PRIVATE = 1;
	private static final int ACCESS_PROTECTED = 2;
	private static final int ACCESS_PUBLIC = 3;

	private static final int PROPERTY_BLANK = 0;
	private static final int PROPERTY_VIRTUAL = 1;
	private static final int PROPERTY_STATIC = 2;
	private static final int PROPERTY_FRIEND = 3;
	private static final int PROPERTY_INTRO = 4;
	private static final int PROPERTY_PURE = 5;
	private static final int PROPERTY_INTRO_PURE = 6;
	private static final int PROPERTY_RESV = 7;

	private static final String[] ACCESS_STRING = new String[4];
	static {
		ACCESS_STRING[0] = "";
		ACCESS_STRING[1] = "private";
		ACCESS_STRING[2] = "protected";
		ACCESS_STRING[3] = "public";

	}
	private static final String[] PROPERTY_STRING = new String[8];
	static {
		PROPERTY_STRING[0] = "";
		PROPERTY_STRING[1] = "virtual";
		PROPERTY_STRING[2] = "static";
		PROPERTY_STRING[3] = "friend";
		PROPERTY_STRING[4] = "<intro>";
		PROPERTY_STRING[5] = "<pure>";
		PROPERTY_STRING[6] = "<intro,pure>";
		PROPERTY_STRING[7] = "";

	}

	//==============================================================================================
	private boolean compilerGenerateFunctionDoesNotExist;
	private boolean cannotBeInherited;
	private boolean cannotBeConstructed;
	private boolean compilerGenerateFunctionDoesExist;
	private boolean cannotBeOverriden;
	private int accessVal;
	private int propertyVal;

	//==============================================================================================
	/**
	 * Constructor for ClassFieldAttributes/
	 * @param reader {@link PdbByteReader} from which this type is deserialized.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	public ClassFieldMsAttributes(PdbByteReader reader) throws PdbException {
		int attributes = reader.parseUnsignedShortVal();
		processAttributes(attributes);
	}

	/**
	 * Returns the value (index) of the Access Value.
	 * @return Index of Access Value.
	 */
	public int getAccessVal() {
		return accessVal;
	}

	/**
	 * Returns the value (index) of the Property Value.
	 * @return Index of Property Value.
	 */
	public int getPropertyVal() {
		return propertyVal;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isAccessBlank() {
		return (accessVal == ACCESS_BLANK);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isAccessPrivate() {
		return (accessVal == ACCESS_PRIVATE);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isAccessProtected() {
		return (accessVal == ACCESS_PROTECTED);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isAccessPublic() {
		return (accessVal == ACCESS_PUBLIC);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isPropertyBlank() {
		return (propertyVal == PROPERTY_BLANK);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isPropertyVirtual() {
		return (propertyVal == PROPERTY_VIRTUAL);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isPropertyStatic() {
		return (propertyVal == PROPERTY_STATIC);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isPropertyFriend() {
		return (propertyVal == PROPERTY_FRIEND);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isPropertyIntro() {
		return (propertyVal == PROPERTY_INTRO);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isPropertyPure() {
		return (propertyVal == PROPERTY_PURE);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isPropertyIntroPure() {
		return (propertyVal == PROPERTY_INTRO_PURE);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isPropertyReserved() {
		return (propertyVal == PROPERTY_RESV);
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isCompilerGeneratedFunctionDoesExist() {
		return compilerGenerateFunctionDoesExist;
	}

	/**
	 * Tells whether the property is true.
	 * @return Truth about the property.
	 */
	public boolean isCannotBeOverriden() {
		return cannotBeOverriden;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(ACCESS_STRING[accessVal]);
		if ((accessVal != 0) && (propertyVal != 0)) {
			builder.append(" ");
		}
		builder.append(PROPERTY_STRING[propertyVal]);
		if (compilerGenerateFunctionDoesNotExist || cannotBeInherited || cannotBeConstructed) {
			DelimiterState ds = new DelimiterState("<", ", ");
			builder.append(ds.out(compilerGenerateFunctionDoesNotExist, "pseudo"));
			builder.append(ds.out(cannotBeInherited, "noinherit"));
			builder.append(ds.out(cannotBeConstructed, "noconstruct"));
			builder.append(">");
		}
	}

	private void processAttributes(int attributes) {
		accessVal = (attributes & 0x0003);
		attributes >>= 2;
		propertyVal = (attributes & 0x0007);
		attributes >>= 3;
		compilerGenerateFunctionDoesNotExist = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		cannotBeInherited = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		cannotBeConstructed = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		compilerGenerateFunctionDoesExist = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		cannotBeOverriden = ((attributes & 0x0001) == 0x0001);
	}

}
