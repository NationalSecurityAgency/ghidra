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
package sarif.export.mm;

import java.io.IOException;

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.data.ISF.IsfObject;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.mem.MemoryBlockType;
import sarif.managers.MemoryMapBytesFile;

public class ExtMemoryMap implements IsfObject {

	String name;
	String kind;
	String overlaySpace;
	String overlayedSpace;
	String comment;
	boolean isVolatile;
	String type;
	String location;

	public ExtMemoryMap(AddressRange range, MemoryBlock block, MemoryMapBytesFile bf, boolean write) throws IOException {

		String permissions = "";
		if (block.isRead()) {
			permissions += "r";
		}
		if (block.isWrite()) {
			permissions += "w";
		}
		if (block.isExecute()) {
			permissions += "x";
		}

		name = block.getName();
		kind = permissions;
		AddressSpace space = range.getAddressSpace();
		if (space instanceof OverlayAddressSpace) {
			OverlayAddressSpace oSpace = (OverlayAddressSpace) space;
			overlaySpace = oSpace.getName();
			overlayedSpace = oSpace.getOverlayedSpace().getName();
		}
		if (block.getComment() != null) {
			comment = block.getComment();
		}
		if (block.isVolatile()) {
			isVolatile = true;
		}
		type = block.getType().name();
		if (block.getType() == MemoryBlockType.BIT_MAPPED || block.getType() == MemoryBlockType.BYTE_MAPPED) {
			// bit mapped blocks can only have one sub-block
			MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
			location = info.getMappedRange().get().getMinAddress().toString();
		} else if (block.isInitialized() && write) {
			location = bf.getFileName() + ":" + bf.getOffset();
			bf.writeBytes(range);
		}
	}

}
