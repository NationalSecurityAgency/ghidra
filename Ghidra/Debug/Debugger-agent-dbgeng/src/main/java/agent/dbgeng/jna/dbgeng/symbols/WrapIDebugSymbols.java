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

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_MODULE_PARAMETERS;
import agent.dbgeng.jna.dbgeng.UnknownWithUtils;

public class WrapIDebugSymbols extends UnknownWithUtils implements IDebugSymbols {
	public static class ByReference extends WrapIDebugSymbols implements Structure.ByReference {
	}

	public WrapIDebugSymbols() {
	}

	public WrapIDebugSymbols(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetNumberModules(ULONGByReference Loaded, ULONGByReference Unloaded) {
		return _invokeHR(VTIndices.GET_NUMBER_MODULES, getPointer(), Loaded, Unloaded);
	}

	@Override
	public HRESULT GetModuleByIndex(ULONG Index, ULONGLONGByReference Base) {
		return _invokeHR(VTIndices.GET_MODULE_BY_INDEX, getPointer(), Index, Base);
	}

	@Override
	public HRESULT GetModuleByModuleName(String Name, ULONG StartIndex, ULONGByReference Index,
			ULONGLONGByReference Base) {
		return _invokeHR(VTIndices.GET_MODULE_BY_MODULE_NAME, getPointer(), Name, StartIndex, Index,
			Base);
	}

	@Override
	public HRESULT GetModuleByOffset(ULONGLONG Offset, ULONG StartIndex, ULONGByReference Index,
			ULONGLONGByReference Base) {
		return _invokeHR(VTIndices.GET_MODULE_BY_OFFSET, getPointer(), Offset, StartIndex, Index,
			Base);
	}

	@Override
	public HRESULT GetModuleNames(ULONG Index, ULONGLONG Base, byte[] ImageNameBuffer,
			ULONG ImageNameBufferSize, ULONGByReference ImageNameSize, byte[] ModuleNameBuffer,
			ULONG ModuleNameBufferSize, ULONGByReference ModuleNameSize,
			byte[] LoadedImageNameBuffer, ULONG LoadedImageNameBufferSize,
			ULONGByReference LoadedImageNameSize) {
		return _invokeHR(VTIndices.GET_MODULE_NAMES, getPointer(), Index, Base, ImageNameBuffer,
			ImageNameBufferSize, ImageNameSize, ModuleNameBuffer, ModuleNameBufferSize,
			ModuleNameSize, LoadedImageNameBuffer, LoadedImageNameBufferSize, LoadedImageNameSize);
	}

	@Override
	public HRESULT GetModuleParameters(ULONG Count, ULONGLONGByReference Bases, ULONG Start,
			DEBUG_MODULE_PARAMETERS.ByReference Params) {
		return _invokeHR(VTIndices.GET_MODULE_PARAMETERS, getPointer(), Count, Bases, Start,
			Params);
	}

	@Override
	public HRESULT StartSymbolMatch(String Pattern, ULONGLONGByReference Handle) {
		return _invokeHR(VTIndices.START_SYMBOL_MATCH, getPointer(), Pattern, Handle);
	}

	@Override
	public HRESULT GetNextSymbolMatch(ULONGLONG Handle, byte[] Buffer, ULONG BufferSize,
			ULONGByReference MatchSize, ULONGLONGByReference Offset) {
		return _invokeHR(VTIndices.GET_NEXT_SYMBOL_MATCH, getPointer(), Handle, Buffer, BufferSize,
			MatchSize, Offset);
	}

	@Override
	public HRESULT EndSymbolMatch(ULONGLONG Handle) {
		return _invokeHR(VTIndices.END_SYMBOL_MATCH, getPointer(), Handle);
	}

	@Override
	public HRESULT GetSymbolPath(byte[] aBuffer, ULONG value, Object object) {
		return _invokeHR(VTIndices.GET_SYMBOL_PATH, getPointer(), aBuffer, value, object);
	}

	@Override
	public HRESULT SetSymbolPath(String Path) {
		return _invokeHR(VTIndices.SET_SYMBOL_PATH, getPointer(), Path);
	}

	@Override
	public HRESULT GetSymbolOptions() {
		return _invokeHR(VTIndices.GET_SYMBOL_OPTIONS, getPointer());
	}

	@Override
	public HRESULT SetSymbolOptions(ULONG Options) {
		return _invokeHR(VTIndices.SET_SYMBOL_OPTIONS, getPointer(), Options);
	}

}
