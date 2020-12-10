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

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

public class WrapIDebugAdvanced2 extends WrapIDebugAdvanced implements IDebugAdvanced2 {
	public static class ByReference extends WrapIDebugAdvanced2 implements Structure.ByReference {
	}

	public WrapIDebugAdvanced2() {
	}

	public WrapIDebugAdvanced2(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT Request(ULONG Request, Pointer InBuffer, ULONG InBuffserSize, Pointer OutBuffer,
			ULONG OutBufferSize, ULONGByReference OutSize) {
		return _invokeHR(VTIndices2.REQUEST, getPointer(), Request, InBuffer, InBuffserSize,
			OutBuffer, OutBufferSize, OutSize);
	}

	@Override
	public HRESULT GetSourceFileInformation(ULONG Which, String SourceFile, ULONGLONG Arg64,
			ULONG Arg32, Pointer Buffer, ULONG BufferSize, ULONGByReference InfoSize) {
		return _invokeHR(VTIndices2.GET_SOURCE_FILE_INFORMATION, getPointer(), Which, SourceFile,
			Arg64, Arg32, Buffer, BufferSize, InfoSize);
	}

	@Override
	public HRESULT FindSourceFileAndToken(ULONG StartElement, ULONGLONG ModAddr, String File,
			ULONG Flags, Pointer FileToken, ULONG FileTokenSize, ULONGByReference FoundElement,
			byte[] Buffer, ULONG BufferSize, ULONGByReference FoundSize) {
		return _invokeHR(VTIndices2.FIND_SOURCE_FILE_AND_TOKEN, getPointer(), StartElement, ModAddr,
			File, Flags, FileToken, FileTokenSize, FoundElement, Buffer, BufferSize, FoundSize);
	}

	@Override
	public HRESULT GetSymbolInformation(ULONG Which, ULONGLONG Arg64, ULONG Arg32, Pointer Buffer,
			ULONG BufferSize, ULONGByReference InfoSize, byte[] StringBuffer,
			ULONG StringBufferSize, ULONGByReference StringSize) {
		return _invokeHR(VTIndices2.GET_SYMBOL_INFORMATION, getPointer(), Which, Arg64, Arg32,
			Buffer, BufferSize, InfoSize, StringBuffer, StringBufferSize, StringSize);
	}

	@Override
	public HRESULT GetSystemObjectInformation(ULONG Which, ULONGLONG Arg64, ULONG Arg32,
			Pointer Buffer, ULONG BufferSize, ULONGByReference InfoSize) {
		return _invokeHR(VTIndices2.GET_SYSTEM_OBJECT_INFORMATION, getPointer(), Which, Arg64,
			Arg32, Buffer, BufferSize, InfoSize);
	}
}
