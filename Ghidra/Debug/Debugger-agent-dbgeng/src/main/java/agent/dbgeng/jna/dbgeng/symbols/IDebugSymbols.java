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

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.IUnknown;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_MODULE_PARAMETERS;
import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugSymbols extends IUnknown {
	final IID IID_IDEBUG_SYMBOLS = new IID("8c31e98c-983a-48a5-9016-6fe5d667a950");

	enum VTIndices implements VTableIndex {
		GET_SYMBOL_OPTIONS, //
		ADD_SYMBOL_OPTIONS, //
		REMOVE_SYMBOL_OPTIONS, //
		SET_SYMBOL_OPTIONS, //
		GET_NAME_BY_OFFSET, //
		GET_OFFSET_BY_NAME, //
		GET_NEAR_NAME_BY_OFFSET, //
		GET_LINE_BY_OFFSET, //
		GET_OFFSET_BY_LINE, //
		GET_NUMBER_MODULES, //
		GET_MODULE_BY_INDEX, //
		GET_MODULE_BY_MODULE_NAME, //
		GET_MODULE_BY_OFFSET, //
		GET_MODULE_NAMES, //
		GET_MODULE_PARAMETERS, //
		GET_SYMBOL_MODULE, //
		GET_TYPE_NAME, //
		GET_TYPE_ID, //
		GET_TYPE_SIZE, //
		GET_FIELD_OFFSET, //
		GET_SYMBOL_TYPE_ID, //
		GET_OFFSET_TYPE_ID, //
		READ_TYPED_DATA_VIRTUAL, //
		WRITE_TYPED_DATA_VIRTUAL, //
		OUTPUT_TYPED_DATA_VIRTUAL, //
		READ_TYPED_DATA_PHYSICAL, //
		WRITE_TYPED_DATA_PHYSICAL, //
		OUTPUT_TYPED_DATA_PHYSICAL, //
		GET_SCOPE, //
		SET_SCOPE, //
		RESET_SCOPE, //
		GET_SCOPE_SYMBOL_GROUP, //
		CREATE_SYMBOL_GROUP, //
		START_SYMBOL_MATCH, //
		GET_NEXT_SYMBOL_MATCH, //
		END_SYMBOL_MATCH, //
		RELOAD, //
		GET_SYMBOL_PATH, //
		SET_SYMBOL_PATH, //
		APPEND_SYMBOL_PATH, //
		GET_IMAGE_PATH, //
		SET_IMAGE_PATH, //
		APPEND_IMAGE_PATH, //
		GET_SOURCE_PATH, //
		GET_SOURCE_PATH_ELEMENT, //
		SET_SOURCE_PATH, //
		APPEND_SOURCE_PATH, //
		FIND_SOURCE_FILE, //
		GET_SOURCE_FILE_LINE_OFFSETS, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT GetNumberModules(ULONGByReference Loaded, ULONGByReference Unloaded);

	HRESULT GetModuleByIndex(ULONG Index, ULONGLONGByReference Base);

	HRESULT GetModuleByModuleName(String Name, ULONG StartIndex, ULONGByReference Index,
			ULONGLONGByReference Base);

	HRESULT GetModuleByOffset(ULONGLONG Offset, ULONG StartIndex, ULONGByReference Index,
			ULONGLONGByReference Base);

	HRESULT GetModuleNames(ULONG Index, ULONGLONG Base, byte[] ImageNameBuffer,
			ULONG ImageNameBufferSize, ULONGByReference ImageNameSize, byte[] ModuleNameBuffer,
			ULONG ModuleNameBufferSize, ULONGByReference ModuleNameSize,
			byte[] LoadedImageNameBuffer, ULONG LoadedImageNameBufferSize,
			ULONGByReference LoadedImageNameSize);

	HRESULT GetModuleParameters(ULONG Count, ULONGLONGByReference Bases, ULONG Start,
			DEBUG_MODULE_PARAMETERS.ByReference Params);

	HRESULT StartSymbolMatch(String Pattern, ULONGLONGByReference Handle);

	HRESULT GetNextSymbolMatch(ULONGLONG Handle, byte[] Buffer, ULONG BufferSize,
			ULONGByReference MatchSize, ULONGLONGByReference Offset);

	HRESULT EndSymbolMatch(ULONGLONG Handle);

	HRESULT GetSymbolPath(byte[] aBuffer, ULONG value, Object object);

	HRESULT SetSymbolPath(String Path);

	HRESULT GetSymbolOptions();

	HRESULT SetSymbolOptions(ULONG Options);

}
