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
 * <code>IBO64DataType</code> provides a Pointer-Typedef BuiltIn for
 * a 64-bit Image Base Offset Relative Pointer.
 */
public class IBO64DataType extends AbstractPointerTypedefDataType {

	static final String NAME = "ibo64";

// TODO: remove old ImageBaseOffset64DataType implementation and uncomment
//	static {
//		ClassTranslator.put("ghidra.program.model.data.ImageBaseOffset64",
//			IBO64DataType.class.getName());
//		ClassTranslator.put("ghidra.program.model.data.ImageBaseOffset64DataType",
//			IBO64DataType.class.getName());
//	}

	/**
	 * Constructs a 64-bit Image Base Offset relative pointer-typedef.
	 */
	public IBO64DataType() {
		this(DataType.DEFAULT, null);
	}

	/**
	 * Constructs a 64-bit Image Base Offset relative pointer-typedef.
	 * @param dtm data-type manager whose data organization should be used
	 */
	public IBO64DataType(DataTypeManager dtm) {
		this(DataType.DEFAULT, dtm);
	}

	/**
	 * Constructs a 64-bit Image Base Offset relative pointer-typedef.
	 * @param referencedDataType data type this pointer-typedef points to
	 */
	public IBO64DataType(DataType referencedDataType) {
		this(referencedDataType, null);
	}

	/**
	 * Constructs a 64-bit Image Base Offset relative pointer-typedef.
	 * @param referencedDataType data type this pointer-typedef points to
	 * @param dtm                data-type manager whose data organization should be used
	 */
	public IBO64DataType(DataType referencedDataType, DataTypeManager dtm) {
		super(null, referencedDataType, 8, dtm);
		PointerTypeSettingsDefinition.DEF.setType(getDefaultSettings(), PointerType.IBO);
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
		IBO64DataType td = new IBO64DataType(getReferencedDataType(), dtm);
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
