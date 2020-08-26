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
 * Class field attributes used on fields within specific PDB data types.
 */
public class ClassFieldMsAttributes extends AbstractParsableItem {

	public enum Access {

		INVALID("", -1), // Our default
		BLANK("", 0),
		PRIVATE("private", 1),
		PROTECTED("protected", 2),
		PUBLIC("public", 3);

		private static final Map<Integer, Access> BY_VALUE = new HashMap<>();
		static {
			for (Access val : values()) {
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

		public static Access fromValue(int val) {
			return BY_VALUE.getOrDefault(val, INVALID);
		}

		private Access(String label, int value) {
			this.label = label;
			this.value = value;
		}

	}

	public enum Property {

		INVALID("", -1),
		BLANK("", 0),
		VIRTUAL("virtual", 1),
		STATIC("static", 2),
		FRIEND("friend", 3),
		INTRO("<intro>", 4),
		PURE("<pure>", 5),
		INTRO_PURE("<intro,pure>", 6),
		RESERVED("", 7);

		private static final Map<Integer, Property> BY_VALUE = new HashMap<>();
		static {
			for (Property val : values()) {
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

		public static Property fromValue(int val) {
			return BY_VALUE.getOrDefault(val, INVALID);
		}

		private Property(String label, int value) {
			this.label = label;
			this.value = value;
		}

	}

	//==============================================================================================
	private boolean compilerGenerateFunctionDoesNotExist;
	private boolean cannotBeInherited;
	private boolean cannotBeConstructed;
	private boolean compilerGenerateFunctionDoesExist;
	private boolean cannotBeOverridden;
	private Access access;
	private Property property;

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
	 * Returns the {@link Access}.
	 * @return the {@link Access}.
	 */
	public Access getAccess() {
		return access;
	}

	/**
	 * Returns the {@link Property}.
	 * @return the {@link Property}.
	 */
	public Property getProperty() {
		return property;
	}

	/**
	 * Tells whether a compiler generated function exists.
	 * @return True if a compiler generated function exists.
	 */
	public boolean isCompilerGeneratedFunctionDoesExist() {
		return compilerGenerateFunctionDoesExist;
	}

	/**
	 * Tells if it cannot be overridden.
	 * @return True if it cannot be overridden.
	 */
	public boolean isCannotBeOverridden() {
		return cannotBeOverridden;
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(access);
		if ((access != Access.BLANK) && (property != Property.BLANK)) {
			builder.append(" ");
		}
		builder.append(property);
		if (compilerGenerateFunctionDoesNotExist || cannotBeInherited || cannotBeConstructed) {
			DelimiterState ds = new DelimiterState("<", ", ");
			builder.append(ds.out(compilerGenerateFunctionDoesNotExist, "pseudo"));
			builder.append(ds.out(cannotBeInherited, "noinherit"));
			builder.append(ds.out(cannotBeConstructed, "noconstruct"));
			builder.append(">");
		}
	}

	private void processAttributes(int attributes) {
		access = Access.fromValue(attributes & 0x0003);
		attributes >>= 2;
		property = Property.fromValue(attributes & 0x0007);
		attributes >>= 3;
		compilerGenerateFunctionDoesNotExist = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		cannotBeInherited = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		cannotBeConstructed = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		compilerGenerateFunctionDoesExist = ((attributes & 0x0001) == 0x0001);
		attributes >>= 1;
		cannotBeOverridden = ((attributes & 0x0001) == 0x0001);
	}

}
