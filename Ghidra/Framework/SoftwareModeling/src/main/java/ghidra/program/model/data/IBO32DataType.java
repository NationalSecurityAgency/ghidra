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

/**
 * <code>IBO32DataType</code> provides a Pointer-Typedef BuiltIn for
 * a 32-bit Image Base Offset Relative Pointer.
 */
public class IBO32DataType extends AbstractPointerTypedefDataType {

	static final String NAME = "ibo32";

// TODO: remove old ImageBaseOffset32DataType implementation and uncomment
//	static {
//		ClassTranslator.put("ghidra.program.model.data.ImageBaseOffset32",
//			IBO32DataType.class.getName());
//		ClassTranslator.put("ghidra.program.model.data.ImageBaseOffset32DataType",
//			IBO32DataType.class.getName());
//	}

	/**
	 * Constructs a 32-bit Image Base Offset relative pointer-typedef.
	 */
	public IBO32DataType() {
		this(DataType.DEFAULT, null);
	}

	/**
	 * Constructs a 32-bit Image Base Offset relative pointer-typedef.
	 * @param dtm data-type manager whose data organization should be used
	 */
	public IBO32DataType(DataTypeManager dtm) {
		this(DataType.DEFAULT, dtm);
	}

	/**
	 * Constructs a 32-bit Image Base Offset relative pointer-typedef.
	 * @param referencedDataType data type this pointer-typedef points to
	 */
	public IBO32DataType(DataType referencedDataType) {
		this(referencedDataType, null);
	}

	/**
	 * Constructs a 32-bit Image Base Offset relative pointer-typedef.
	 * @param referencedDataType data type this pointer-typedef points to
	 * @param dtm                data-type manager whose data organization should be used
	 */
	public IBO32DataType(DataType referencedDataType, DataTypeManager dtm) {
		super(null, referencedDataType, 4, dtm);
		PointerTypeSettingsDefinition.DEF.setType(getDefaultSettings(), PointerType.IBO);
	}

	@Override
	public String getDescription() {
		return "32-bit Image Base Offset Relative Pointer-Typedef";
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dataMgr == dtm) {
			return this;
		}
		IBO32DataType td = new IBO32DataType(getReferencedDataType(), dtm);
		TypedefDataType.copyTypeDefSettings(this, td, false);
		return td;
	}

	@Override
	public String getName() {
		DataType dt = getReferencedDataType();
		if (dt == null || Undefined.isUndefined(dt) || (dt instanceof VoidDataType)) {
			return NAME; // use simple ibo name
		}
		return super.getName(); // use generated named
	}

}
