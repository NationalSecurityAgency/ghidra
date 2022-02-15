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

import ghidra.docking.settings.Settings;
import ghidra.util.classfinder.ClassTranslator;

/**
 * <code>IBO64DataType</code> provides a Pointer-Typedef BuiltIn for
 * a 64-bit Image Base Offset Relative Pointer.  This {@link TypeDef} implementation 
 * specifies the {@link PointerType#IMAGE_BASE_RELATIVE} attribute/setting
 * associated with a 64-bit {@link Pointer}.
 * <br>
 * This class replaces the use of the old <code>ImageBaseOffset64DataType</code>
 * which did not implement the Pointer interface.  This is an alternative 
 * {@link BuiltIn} implementation to using the more general {@link PointerTypedef}
 * datatype with an unspecified referenced datatype.  {@link PointerTypedef} should 
 * be used for other cases 
 * (see {@link #createIBO64PointerTypedef(DataType)}).
 */
public class IBO64DataType extends AbstractPointerTypedefBuiltIn {

	public static final IBO64DataType dataType = new IBO64DataType();

	static final String NAME = "ImageBaseOffset64";

	private static TypeDefSettingsDefinition[] IBO_TYPEDEF_SETTINGS_DEFS =
		{ PointerTypeSettingsDefinition.DEF };

	static {
		ClassTranslator.put("ghidra.program.model.data.ImageBaseOffset64",
			IBO64DataType.class.getName());
		ClassTranslator.put("ghidra.program.model.data.ImageBaseOffset64DataType",
			IBO64DataType.class.getName());
	}

	/**
	 * Constructs a 64-bit Image Base Offset relative pointer-typedef.
	 */
	public IBO64DataType() {
		this(null);
	}

	/**
	 * Constructs a 64-bit Image Base Offset relative pointer-typedef.
	 * @param dtm data-type manager whose data organization should be used
	 */
	public IBO64DataType(DataTypeManager dtm) {
		super(NAME, null, 8, dtm);
		PointerTypeSettingsDefinition.DEF.setType(getDefaultSettings(), PointerType.IMAGE_BASE_RELATIVE);
	}

	@Override
	public String getDescription() {
		return "64-bit Image Base Offset Relative Pointer-Typedef";
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dataMgr == dtm) {
			return this;
		}
		return new IBO64DataType(dtm);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "ibo64";
	}
	
	@Override
	public TypeDefSettingsDefinition[] getBuiltInSettingsDefinitions() {
		return IBO_TYPEDEF_SETTINGS_DEFS;
	}

	/**
	 * Create a IBO64 {@link PointerTypedef} with auto-naming.  If needed, a name and category
	 * may be assigned to the returned instance.  Unlike using an immutable {@link IBO32DataType} instance
	 * the returned instance is mutable.
	 * @param referencedDataType referenced datatype or null
	 * @return new IBO64 pointer-typedef
	 */
	public static PointerTypedef createIBO64PointerTypedef(DataType referencedDataType) {
		return new PointerTypedef(null, referencedDataType, 8,
			referencedDataType != null ? referencedDataType.getDataTypeManager() : null,
			PointerType.IMAGE_BASE_RELATIVE);
	}

}
