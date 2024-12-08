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

import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.ISF.IsfComponent;
import ghidra.program.model.data.ISF.IsfObject;

public class ExtIsfComponent extends IsfComponent {
	
	Integer bitOffset;
	Integer bitSize;
	
	public ExtIsfComponent(DataTypeComponent component, IsfObject typeObj) {
		super(component, typeObj);
		if (component.isBitFieldComponent()) {
			BitFieldDataType dt = (BitFieldDataType) component.getDataType();
			bitOffset = dt.getBitOffset();
			bitSize = dt.getBitSize();
		}
	}

}
