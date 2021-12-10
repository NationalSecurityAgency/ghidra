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
package ghidra.file.formats.android.oat.oatclass;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.android.oat.OatConstants;
import ghidra.file.formats.android.oat.oatmethod.OatMethodOffsets;
import ghidra.program.model.data.DataType;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

/**
 * Base class for OatClass versions
 *
 */
public abstract class OatClass implements StructConverter {

	protected String oatVersion;

	protected short status_;
	protected short type_;

	protected List<OatMethodOffsets> methods_pointer_ = new ArrayList<OatMethodOffsets>();

	protected OatClassStatusEnum statusEnum;

	protected OatClass(BinaryReader reader, String oatVersion) throws IOException {

		this.oatVersion = oatVersion;

		status_ = reader.readNextShort();

		switch (oatVersion) {
			case OatConstants.VERSION_KITKAT_RELEASE: {
				statusEnum = OatClassStatusEnum_K.kStatusInitialized.get(status_);
				break;
			}
			case OatConstants.VERSION_LOLLIPOP_RELEASE:
			case OatConstants.VERSION_LOLLIPOP_MR1_FI_RELEASE:
			case OatConstants.VERSION_LOLLIPOP_WEAR_RELEASE:
			case OatConstants.VERSION_MARSHMALLOW_RELEASE:
			case OatConstants.VERSION_NOUGAT_RELEASE:
			case OatConstants.VERSION_NOUGAT_MR1_RELEASE: {
				statusEnum = OatClassStatusEnum_L_M_N.kStatusMax.get(status_);
				break;
			}
			case OatConstants.VERSION_OREO_RELEASE: {
				statusEnum = OatClassStatusEnum_O.kStatusMax.get(status_);
				break;
			}
			case OatConstants.VERSION_OREO_M2_RELEASE: {
				statusEnum = OatClassStatusEnum_O_M2.kStatusMax.get(status_);
				break;
			}
			case OatConstants.VERSION_PIE_RELEASE:
			case OatConstants.VERSION_10_RELEASE: {
				statusEnum = OatClassStatusEnum_P_10.kLast.get(status_);
				break;
			}
			case OatConstants.VERSION_11_RELEASE:
			case OatConstants.VERSION_12_RELEASE: {
				statusEnum = OatClassStatusEnum_11_12.kLast.get(status_);
				break;
			}
			default: {
				statusEnum = new OatClassStatusEnum_Invalid(status_);
				break;
			}
		}
	}

	/**
	 * State of class during compilation
	 * @return the class status
	 */
	public final short getStatus() {
		return status_;
	}

	public final OatClassType getType() {
		for (OatClassType type : OatClassType.values()) {
			if (type.ordinal() == type_) {
				return type;
			}
		}
		return OatClassType.kOatClassMax;//invalid state
	}

	/**
	 * methodOffsets is a list of offset that points to the generated
	 * native code for each compiled method.    
	 * @return list of method offsets
	 */
	public final List<OatMethodOffsets> getMethodOffsets() {
		return methods_pointer_;
	}

	/**
	 * Returns true if this method index is declared native in the bitmap
	 * @param methodIndex the method index
	 * @return true if this method index is declared native in the bitmap
	 */
	public abstract boolean isMethodNative(int methodIndex);

	/**
	 * Renames the data type with the specified prefix.
	 * Prefix is delimited by the second underscore character.
	 * If no underscore exist, then entire data type name is changed to the prefix.
	 * @param dataType the data type to rename
	 * @param prefix the prefix to use in data type name
	 * @throws InvalidNameException if the name is invalid
	 * @throws DuplicateNameException if the name already exists.
	 */
	protected void renameDataType(DataType dataType, String prefix)
			throws InvalidNameException, DuplicateNameException {
		String currentName = dataType.getName();
		int underscorePos = currentName.indexOf('_');
		underscorePos = currentName.indexOf('_', underscorePos + 1);
		if (underscorePos == -1) {
			dataType.setName(prefix);
		}
		else {
			dataType.setName(prefix + currentName.substring(underscorePos));
		}
	}
}
