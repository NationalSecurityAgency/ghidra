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
package ghidra.file.formats.android.oat;

/**
 * OatMethodOffsets are currently 5x32-bits=160-bits long, so if we can
 * save even one OatMethodOffsets struct, the more complicated encoding
 * using a bitmap pays for itself since few classes will have 160
 * methods.
 * 
 * https://android.googlesource.com/platform/art/+/lollipop-release/runtime/oat.h#152
 * 
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
	kOatClassMax//3
}
