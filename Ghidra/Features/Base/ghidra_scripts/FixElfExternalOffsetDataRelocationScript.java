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
//
// With ELF imports performed with Ghidra 10.0 and 10.1 certain data relocations
// which corresponded to symbol pointers with an additional offset produced an 
// ERROR bookmark and was not applied.  With Ghidra 10.2 such locations now
// get the relocation applied and should utilize a Pointer-Typedef with an
// pointer offset setting.  Use of a normal pointer will produce an invalid 
// reference which was the original reason we avoided applying the relocation.
//
// This script applies the correct relocaton by modifying the memory bytes
// at all bookmarked locations and applies a WARNING bookmark.  If data has been
// applied script will attempt to correct using an offset pointer-typedef.
//
// Script may be constrained by a selection.
//
//@category ELF Relocations
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.elf.relocation.ElfRelocationHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.util.GhidraDataConverter;
import ghidra.util.Msg;

public class FixElfExternalOffsetDataRelocationScript extends GhidraScript {

	private static final String EXT_RELO_BOOKMARK_CATEGORY = "EXTERNAL Relocation";
	private static final String EXT_RELO_BOOKMARK_TEXT_PREFIX =
		"Unsupported EXTERNAL Data Elf Relocation: External Location =";

	@Override
	protected void run() throws Exception {

		if (currentProgram == null) {
			popup("No active program");
			return;
		}

		MessageLog log = new MessageLog(); // throw-away log

		Iterator<Bookmark> errorBookmarks =
			currentProgram.getBookmarkManager().getBookmarksIterator(BookmarkType.ERROR);
		while (errorBookmarks.hasNext()) {
			Bookmark b = errorBookmarks.next();
			if (EXT_RELO_BOOKMARK_CATEGORY.equals(b.getCategory()) &&
				b.getComment().startsWith(EXT_RELO_BOOKMARK_TEXT_PREFIX)) {
				if (currentSelection != null && !currentSelection.contains(b.getAddress())) {
					continue;
				}
				try {
					if (!updateExternalDataRelocation(b, log)) {
						Msg.error(this,
							"Failed to update EXTERNAL relocation at " + b.getAddress());
					}
				}
				catch (Exception e) {
					Msg.error(this, "Error occured while updating EXTERNAL relocation at " +
						b.getAddress() + ": " + e.getMessage());
				}
			}
		}
	}

	private boolean updateExternalDataRelocation(Bookmark relocErrorBookmark, MessageLog log) throws Exception {
		
		Address address = relocErrorBookmark.getAddress();
		String bookmarkComment = relocErrorBookmark.getComment();
		
		int byteSize = address.getAddressSpace().getPointerSize();
		
		int index = bookmarkComment.lastIndexOf("0x");
		if (index < 0) {
			return false;
		}
		
		char signChar = bookmarkComment.charAt(index - 1);
		int offset;
		try {
			offset = Integer.parseInt(bookmarkComment.substring(index + 2), 16);
		}
		catch (NumberFormatException e) {
			return false;
		}
		if (signChar == '-') {
			offset = -offset;
		}
		else if (signChar != '+') {
			return false;
		}
		
		Memory memory = currentProgram.getMemory();
		DumbMemBufferImpl buf = new DumbMemBufferImpl(memory, address);
		
		Address symbolAddr = PointerDataType.getAddressValue(buf, byteSize, address.getAddressSpace());
		if (symbolAddr == null) {
			return false; // invalid pointer data
		}
		
		String symbolName = bookmarkComment.substring(EXT_RELO_BOOKMARK_TEXT_PREFIX.length(), index - 1).trim();
		if (currentProgram.getSymbolTable().getSymbol(symbolName, symbolAddr, null) == null) {
			return false; // EXTERNAL block symbol not found at stored address
		}

		Listing listing = currentProgram.getListing();
		Data data = listing.getDataContaining(address);
		if (data == null) {
			return false; // possible instruction applied
		}

		DataType dt = data.getDataType();
		boolean isDefaultTypeApplied = address.equals(data.getAddress()) &&
			(Undefined.isUndefined(dt) || isDefaultPointer(dt));
		int componentOffset = (int) address.subtract(data.getAddress());
		if (!isDefaultTypeApplied &&
			!canFixupStructure(dt, componentOffset, address.getPointerSize())) {
			return false; // unsupported datatype applied
		}
		
		long newValue = symbolAddr.getOffset() + offset;
		
		GhidraDataConverter converter = GhidraDataConverter.getInstance(buf.isBigEndian());
		byte[] bytes = new byte[byteSize];
		converter.putValue(newValue, byteSize, bytes, 0);
		memory.setBytes(address, bytes);

		currentProgram.getBookmarkManager().removeBookmark(relocErrorBookmark);
		
		ElfRelocationHandler.warnExternalOffsetRelocation(currentProgram, address, symbolAddr, symbolName, offset, log);
		
		DataType offsetPtrDt =
			currentProgram.getDataTypeManager()
					.resolve(new PointerTypedef(null, null, -1, currentProgram.getDataTypeManager(),
						offset), null);
		
		if (isDefaultTypeApplied) {
			// Replace undefined/default data with offset-pointer
			DataUtilities.createData(currentProgram, address, offsetPtrDt, -1,
				ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		}
		else {
			Structure s = (Structure) dt;
			DataTypeComponent dtc = s.getComponentAt(componentOffset);
			if (!offsetPtrDt.isEquivalent(dtc.getDataType())) {
				s.replace(dtc.getOrdinal(), offsetPtrDt, -1);
			}
			ReferenceManager refMgr = currentProgram.getReferenceManager();
			Reference ref = refMgr.getPrimaryReferenceFrom(address, 0);
			if (ref != null && symbolAddr.equals(ref.getToAddress())) {
				// Replace reference with default offset reference
				refMgr.delete(ref);
				refMgr.addOffsetMemReference(address, symbolAddr, true, offset, RefType.DATA,
					SourceType.DEFAULT, 0);
			}
		}
		return true;
	}

	private boolean isDefaultPointer(DataType dt) {
		if (dt instanceof Pointer) {
			DataType refDt = ((Pointer) dt).getDataType();
			return refDt == null || refDt == DataType.DEFAULT;
		}
		return false;
	}

	private boolean canFixupStructure(DataType dt, int componentOffset, int pointerLength) {
		if (!(dt instanceof Structure)) {
			return false;
		}
		Structure s = (Structure) dt;
		DataTypeComponent dtc = s.getComponentAt(componentOffset);
		if (dtc.getLength() != pointerLength) {
			return false;
		}
		DataType cdt = dtc.getDataType();
		if (cdt instanceof Pointer) {
			return true;
		}

		// Check for case where structure may already have been modified
		if (cdt instanceof TypeDef) {
			TypeDef td = (TypeDef) cdt;
			if (!(td.getDataType() instanceof Pointer)) {
				return false;
			}
			if (!td.isAutoNamed()) {
				return false;
			}
			return true;
		}
		return false;
	}

}
