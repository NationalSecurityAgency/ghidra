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

import java.lang.reflect.Field;

import ghidra.program.model.data.*;

/**
 * OatMethodOffsets are currently 5x32-bits=160-bits long, so if we can
 * save even one OatMethodOffsets struct, the more complicated encoding
 * using a bitmap pays for itself since few classes will have 160
 * methods.
 * 
 * <a href="https://android.googlesource.com/platform/art/+/lollipop-release/runtime/oat.h#152">lollipop-release/runtime/oat.h</a>
 * <br>
 * <a href="https://android.googlesource.com/platform/art/+/refs/heads/android-s-beta-5/runtime/oat_file.h#66">android-s-beta-5/runtime/oat_file.h</a>
 */
public enum OatClassType {

	/**
	 * OatClass is followed by an OatMethodOffsets for each method.
	 */
	kOatClassAllCompiled,//0 
	/**
	 * A bitmap of which OatMethodOffsets are present follows the OatClass.
	 */
	kOatClassSomeCompiled,//1
	/**
	 * All methods are interpreted so no OatMethodOffsets are necessary.
	 */
	kOatClassNoneCompiled,//2
	/**
	 * Possibly an invalid case?
	 * From "oat_file.cc":
	 * 		. . . 
	 * 		case kOatClassMax: {
	 * 			LOG(FATAL) << "Invalid OatClassType " << type_;
	 * 			break;
	 * 		}
	 * 		. . .
	 */
	kOatClassMax;//3

	/**
	 * Converts this ENUM into a data type.
	 * @return this ENUM converted into a data type
	 */
	public static DataType toData() {
		EnumDataType enumDataType =
			new EnumDataType(OatClassType.class.getSimpleName(), 2);
		for (Field field : OatClassType.class.getDeclaredFields()) {
			try {
				OatClassType obj = (OatClassType) field.get(null);
				enumDataType.add(field.getName(), (short)obj.ordinal());
			}
			catch (Exception e) {
				//ignore...
			}
		}
		enumDataType.setCategoryPath(new CategoryPath("/oat"));
		return enumDataType;
	}
}
