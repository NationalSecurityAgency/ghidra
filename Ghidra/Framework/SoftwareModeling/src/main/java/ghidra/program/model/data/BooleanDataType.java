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
package ghidra.program.model.data;

import java.math.BigInteger;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.lang.DecompilerLanguage;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Provides a definition of an Ascii byte in a program.
 */
public class BooleanDataType extends AbstractIntegerDataType {

	private static SettingsDefinition[] SETTINGS_DEFS = {};

	public static final BooleanDataType dataType = new BooleanDataType();

	/**
	 * Constructs a new Boolean datatype.
	 */
	public BooleanDataType() {
		this(null);
	}

	public BooleanDataType(DataTypeManager dtm) {
		super("bool", false, dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "bool";
	}

	@Override
	public String getDecompilerDisplayName(DecompilerLanguage language) {
		if (language == DecompilerLanguage.JAVA_LANGUAGE) {
			return "boolean";
		}
		return name;
	}

	@Override
	public String getCDeclaration() {
		return name;
	}

	@Override
	public int getLength() {
		return 1; // TODO: Size should probably be based upon data organization
	}

	@Override
	public String getDescription() {
		return "Boolean";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try {
			return buf.getByte(0) != 0;
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Boolean.class;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		Boolean b = (Boolean) getValue(buf, settings, length);
		if (b == null) {
			return "??";
		}
		return b.booleanValue() ? "TRUE" : "FALSE";
	}

	@Override
	public String getRepresentation(BigInteger bigInt, Settings settings, int bitLength) {
		return BigInteger.ZERO.equals(bigInt) ? "FALSE" : "TRUE";
	}

	@Override
	protected SettingsDefinition[] getBuiltInSettingsDefinitions() {
		return SETTINGS_DEFS;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		return new BooleanDataType(dtm);
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "BOOL";
	}

	@Override
	public AbstractIntegerDataType getOppositeSignednessDataType() {
		// TODO: only unsigned supported
		return this;
	}

}
