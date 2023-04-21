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

import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.ISF.IsfDataTypeWriter.Exclude;

public class IsfDataTypeBitField implements IsfObject {

	public String kind;
	public Integer bit_length;
	public Integer bit_position;
	public IsfObject type;

	@Exclude
	public Integer bit_offset;
	@Exclude
	private int storage_size;

	public IsfDataTypeBitField(BitFieldDataType bf, int componentOffset, IsfObject typeObj) {
		kind = IsfUtilities.getKind(bf);
		bit_length = bf.getBitSize();
		bit_offset = bf.getBitOffset();
		bit_position = componentOffset % 4 * 8 + bit_offset;
		type = typeObj;

		storage_size = bf.getStorageSize();
	}

}
