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
package agent.dbgeng.jna.dbgeng.symbols;

import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_MODULE_AND_ID;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_SYMBOL_ENTRY;
import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugSymbols3 extends IDebugSymbols2 {
	final IID IID_IDEBUG_SYMBOLS3 = new IID("f02fbecc-50ac-4f36-9ad9-c975e8f32ff8");

	enum VTIndices3 implements VTableIndex {
		GET_NAME_BY_OFFSET_WIDE, //
		GET_OFFSET_BY_NAME_WIDE, //
		GET_NEAR_NAME_BY_OFFSET_WIDE, //
		GET_LINE_BY_OFFSET_WIDE, //
		GET_OFFSET_BY_LINE_WIDE, //
		GET_MODULE_BY_MODULE_NAME_WIDE, //
		GET_SYMBOL_MODULE_WIDE, //
		GET_TYPED_NAME_WIDE, //
		GET_TYPE_ID_WIDE, //
		GET_FIELD_OFFSET_WIDE, //
		GET_SYMBOL_TYPE_ID_WIDE, //
		GET_SCOPE_SYMBOL_GROUP2, //
		CREATE_SYMBOL_GROUP2, //
		START_SYMBOL_MATCH_WIDE, //
		GET_NEXT_SYMBOL_MATCH_WIDE, //
		RELOAD_WIDE, //
		GET_SYMBOL_PATH_WIDE, //
		SET_SYMBOL_PATH_WIDE, //
		APPEND_SYMBOL_PATH_WIDE, //
		GET_IMAGE_PATH_WIDE, //
		SET_IMAGE_PATH_WIDE, //
		APPEND_IMAGE_PATH_WIDE, //
		GET_SOURCE_PATH_WIDE, //
		GET_SOURCE_PATH_ELEMENT_WIDE, //
		SET_SOURCE_PATH_WIDE, //
		APPEND_SOURCE_PATH_WIDE, //
		FIND_SOURCE_FILE_WIDE, //
		GET_SOURCE_FILE_LINE_OFFSETS_WIDE, //
		GET_MODULE_VERSION_INFORMATION_WIDE, //
		GET_MODULE_NAME_STRING_WIDE, //
		GET_CONSTANT_NAME_WIDE, //
		GET_FIELD_NAME_WIDE, //
		IS_MANAGED_MODULE, //
		GET_MODULE_BY_MODULE_NAME2, //
		GET_MODULE_BY_MODULE_NAME2_WIDE, //
		GET_MODULE_BY_OFFSET2, //
		ADD_SYNTHETIC_MODULE, //
		ADD_SYNTHETIC_MODULE_WIDE, //
		REMOVE_SYNTHETIC_MODULE, //
		GET_CURRENT_SCOPE_FRAME_INDEX, //
		SET_SCOPE_FRAME_BY_INDEX, //
		SET_SCOPE_FROM_JIT_DEBUG_INFO, //
		SET_SCOPE_FROM_STORED_EVENT, //
		OUTPUT_SYMBOL_BY_OFFSET, //
		GET_FUNCTION_ENTRY_BY_OFFSET, //
		GET_FIELD_TYPE_AND_OFFSET, //
		GET_FIELD_TYPE_AND_OFFSET_WIDE, //
		ADD_SYNTHETIC_SYMBOL, //
		ADD_SYNTHETIC_SYMBOL_WIDE, //
		REMOVE_SYNTHETIC_SYMBOL, //
		GET_SYMBOL_ENTRIES_BY_OFFSET, //
		GET_SYMBOL_ENTRIES_BY_NAME, //
		GET_SYMBOL_ENTRIES_BY_NAME_WIDE, //
		GET_SYMBOL_ENTRY_BY_TOKEN, //
		GET_SYMBOL_ENTRY_INFORMATION, //
		GET_SYMBOL_ENTRY_STRING, //
		GET_SYMBOL_ENTRY_STRING_WIDE, //
		GET_SYMBOL_ENTRY_OFFSET_REGIONS, //
		GET_SYMBOL_ENTRY_BY_SYMBOL_ENTRY, //
		GET_SOURCE_ENTRIES_BY_OFFSET, //
		GET_SOURCE_ENTRIES_BY_LINE, //
		GET_SOURCE_ENTRIES_BY_LINE_WIDE, //
		GET_SOURCE_ENTRY_STRING, //
		GET_SOURCE_ENTRY_STRING_WIDE, //
		GET_SOURCE_ENTRY_OFFSET_REGIONS, //
		GET_SOURCE_ENTRY_BY_SOURCE_ENTRY, //
		;

		static int start = VTableIndex.follow(VTIndices2.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetCurrentScopeFrameIndex(ULONGByReference Index);

	HRESULT SetCurrentScopeFrameIndex(ULONG Index);

	HRESULT GetModuleByModuleNameWide(WString Name, ULONG StartIndex, ULONGByReference Index,
			ULONGLONGByReference Base);

	HRESULT GetModuleNameStringWide(ULONG Which, ULONG Index, ULONGLONG Base, char[] Buffer,
			ULONG BufferSize, ULONGByReference NameSize);

	HRESULT GetSymbolEntriesByName(String Symbol, ULONG Flags, DEBUG_MODULE_AND_ID[] Ids,
			ULONG IdsCount, ULONGByReference Entries);

	HRESULT GetSymbolEntriesByNameWide(WString Symbol, ULONG Flags, DEBUG_MODULE_AND_ID[] Ids,
			ULONG IdsCount, ULONGByReference Entries);

	HRESULT GetSymbolEntryInformation(DEBUG_MODULE_AND_ID Id, DEBUG_SYMBOL_ENTRY.ByReference Info);

	HRESULT GetSymbolEntryString(DEBUG_MODULE_AND_ID Id, ULONG Which, byte[] Buffer,
			ULONG BufferSize, ULONGByReference StringSize);

	HRESULT GetSymbolEntryStringWide(DEBUG_MODULE_AND_ID Id, ULONG Which, char[] Buffer,
			ULONG BufferSize, ULONGByReference StringSize);
}
