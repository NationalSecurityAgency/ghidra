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
package agent.dbgeng.jna.dbgeng.advanced;

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

public class WrapIDebugAdvanced3 extends WrapIDebugAdvanced2 implements IDebugAdvanced3 {
	public static class ByReference extends WrapIDebugAdvanced3 implements Structure.ByReference {
	}

	public WrapIDebugAdvanced3() {
	}

	public WrapIDebugAdvanced3(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT GetSourceFileInformationWide(ULONG Which, WString SourceFile, ULONGLONG Arg64,
			ULONG Arg32, Pointer Buffer, ULONG BufferSize, ULONGByReference InfoSize) {
		return _invokeHR(VTIndices3.GET_SOURCE_FILE_INFORMATION_WIDE, getPointer(), Which,
			SourceFile, Arg64, Arg32, Buffer, BufferSize, InfoSize);
	}

	@Override
	public HRESULT FindSourceFileAndTokenWide(ULONG StartElement, ULONGLONG ModAddr, String File,
			ULONG Flags, Pointer FileToken, ULONG FileTokenSize, ULONGByReference FoundElement,
			char[] Buffer, ULONG BufferSize, ULONGByReference FoundSize) {
		return _invokeHR(VTIndices3.FIND_SOURCE_FILE_AND_TOKEN_WIDE, getPointer(), StartElement,
			ModAddr, File, Flags, FileToken, FileTokenSize, FoundElement, Buffer, BufferSize,
			FoundSize);
	}

	@Override
	public HRESULT GetSymbolInformationWide(ULONG Which, ULONGLONG Arg64, ULONG Arg32,
			Pointer Buffer, ULONG BufferSize, ULONGByReference InfoSize, char[] StringBuffer,
			ULONG StringBufferSize, ULONGByReference StringSize) {
		return _invokeHR(VTIndices3.GET_SYMBOL_INFORMATION_WIDE, getPointer(), Which, Arg64, Arg32,
			Buffer, BufferSize, InfoSize, StringBuffer, StringBufferSize, StringSize);
	}
}
