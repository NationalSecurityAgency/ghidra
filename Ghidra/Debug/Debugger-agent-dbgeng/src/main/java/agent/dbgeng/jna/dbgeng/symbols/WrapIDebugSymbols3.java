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

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_MODULE_AND_ID;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_SYMBOL_ENTRY;

public class WrapIDebugSymbols3 extends WrapIDebugSymbols2 implements IDebugSymbols3 {
	public static class ByReference extends WrapIDebugSymbols3 implements Structure.ByReference {
	}

	public WrapIDebugSymbols3() {
	}

	public WrapIDebugSymbols3(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetCurrentScopeFrameIndex(ULONGByReference Index) {
		return _invokeHR(VTIndices3.GET_CURRENT_SCOPE_FRAME_INDEX, getPointer(), Index);
	}

	@Override
	public HRESULT SetCurrentScopeFrameIndex(ULONG Index) {
		return _invokeHR(VTIndices3.SET_SCOPE_FRAME_BY_INDEX, getPointer(), Index);
	}

	@Override
	public HRESULT GetModuleByModuleNameWide(WString Name, ULONG StartIndex, ULONGByReference Index,
			ULONGLONGByReference Base) {
		return _invokeHR(VTIndices3.GET_MODULE_BY_MODULE_NAME_WIDE, getPointer(), Name, StartIndex,
			Index, Base);
	}

	@Override
	public HRESULT GetModuleNameStringWide(ULONG Which, ULONG Index, ULONGLONG Base, char[] Buffer,
			ULONG BufferSize, ULONGByReference NameSize) {
		return _invokeHR(VTIndices3.GET_MODULE_NAME_STRING_WIDE, getPointer(), Which, Index, Base,
			Buffer, BufferSize, NameSize);
	}

	@Override
	public HRESULT GetSymbolEntriesByName(String Symbol, ULONG Flags, DEBUG_MODULE_AND_ID[] Ids,
			ULONG IdsCount, ULONGByReference Entries) {
		return _invokeHR(VTIndices3.GET_SYMBOL_ENTRIES_BY_NAME, getPointer(), Symbol, Flags, Ids,
			IdsCount, Entries);
	}

	@Override
	public HRESULT GetSymbolEntriesByNameWide(WString Symbol, ULONG Flags,
			DEBUG_MODULE_AND_ID[] Ids, ULONG IdsCount, ULONGByReference Entries) {
		return _invokeHR(VTIndices3.GET_SYMBOL_ENTRIES_BY_NAME_WIDE, getPointer(), Symbol, Flags,
			Ids, IdsCount, Entries);
	}

	@Override
	public HRESULT GetSymbolEntryInformation(DEBUG_MODULE_AND_ID Id,
			DEBUG_SYMBOL_ENTRY.ByReference Info) {
		return _invokeHR(VTIndices3.GET_SYMBOL_ENTRY_INFORMATION, getPointer(), Id, Info);
	}

	@Override
	public HRESULT GetSymbolEntryString(DEBUG_MODULE_AND_ID Id, ULONG Which, byte[] Buffer,
			ULONG BufferSize, ULONGByReference StringSize) {
		return _invokeHR(VTIndices3.GET_SYMBOL_ENTRY_STRING, getPointer(), Id, Which, Buffer,
			BufferSize, StringSize);
	}

	@Override
	public HRESULT GetSymbolEntryStringWide(DEBUG_MODULE_AND_ID Id, ULONG Which, char[] Buffer,
			ULONG BufferSize, ULONGByReference StringSize) {
		return _invokeHR(VTIndices3.GET_SYMBOL_ENTRY_STRING_WIDE, getPointer(), Id, Which, Buffer,
			BufferSize, StringSize);
	}
}
