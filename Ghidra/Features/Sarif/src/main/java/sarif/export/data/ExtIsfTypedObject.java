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
package sarif.export.data;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ISF.IsfBuiltIn;
import ghidra.program.model.data.ISF.IsfDataTypeDefault;
import ghidra.program.model.data.ISF.IsfEnum;
import ghidra.program.model.data.ISF.IsfObject;
import ghidra.program.model.data.ISF.IsfTypedObject;

public class ExtIsfTypedObject extends IsfTypedObject {
	
	String typeLocation;

	public ExtIsfTypedObject(DataType dt, IsfObject typeObj) {
		super(dt, typeObj);
		if (typeObj instanceof IsfDataTypeDefault) {
			typeLocation = ((IsfDataTypeDefault) typeObj).location;
			return;
		}
		if (typeObj instanceof ExtIsfComposite) {
			typeLocation = ((ExtIsfComposite) typeObj).location;
		}
		if (typeObj instanceof IsfEnum) {
			typeLocation = ((IsfEnum) typeObj).location;
		}
		if (typeObj instanceof ExtIsfTypedefBase) {
			typeLocation = ((ExtIsfTypedefBase) typeObj).location;
		}
//		if (typeObj instanceof IsfTypedefIntegral) {
//			typeLocation = ((IsfTypedefIntegral) typeObj).location;
//		}
		if (typeObj instanceof ExtIsfTypedefPointer) {
			typeLocation = ((ExtIsfTypedefPointer) typeObj).location;
		}
		if (typeObj instanceof ExtIsfTypedObject) {
			typeLocation = ((ExtIsfTypedObject) typeObj).location;
		}
		if (typeObj instanceof IsfBuiltIn) {
			typeLocation = ((IsfBuiltIn) typeObj).location;
		}
	}

}
