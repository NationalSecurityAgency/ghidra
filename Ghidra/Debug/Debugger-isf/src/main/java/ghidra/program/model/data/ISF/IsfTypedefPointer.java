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
package ghidra.program.model.data.ISF;

import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TypeDef;

public class IsfTypedefPointer extends AbstractIsfObject {

	public Integer size;
	public String kind;
	public String endian;
	public IsfObject type;

	public IsfTypedefPointer(TypeDef typeDef) {
		super(typeDef);
		Pointer ptr;
		if (typeDef != null) {
			ptr = (Pointer) typeDef.getBaseDataType();
		} 
		else {
			ptr = new PointerDataType();
		}
		size = ptr.hasLanguageDependantLength() ? -1 : ptr.getLength();
		kind = "typedef";
		endian = IsfUtilities.getEndianness(ptr);
		type = new IsfPointer(ptr);
	}

}
