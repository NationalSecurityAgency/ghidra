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
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugAdvanced2 extends IDebugAdvanced {
	final IID IID_IDEBUG_ADVANCED2 = new IID("716d14c9-119b-4ba5-af1f-0890e672416a");

	enum VTIndices2 implements VTableIndex {
		REQUEST, //
		GET_SOURCE_FILE_INFORMATION, //
		FIND_SOURCE_FILE_AND_TOKEN, //
		GET_SYMBOL_INFORMATION, //
		GET_SYSTEM_OBJECT_INFORMATION, //
		;

		static int start = VTableIndex.follow(VTIndices.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT Request(ULONG Request, Pointer InBuffer, ULONG InBuffserSize, Pointer OutBuffer,
			ULONG OutBufferSize, ULONGByReference OutSize);

	HRESULT GetSourceFileInformation(ULONG Which, String SourceFile, ULONGLONG Arg64, ULONG Arg32,
			Pointer Buffer, ULONG BufferSize, ULONGByReference InfoSize);

	HRESULT FindSourceFileAndToken(ULONG StartElement, ULONGLONG ModAddr, String File, ULONG Flags,
			Pointer FileToken, ULONG FileTokenSize, ULONGByReference FoundElement, byte[] Buffer,
			ULONG BufferSize, ULONGByReference FoundSize);

	HRESULT GetSymbolInformation(ULONG Which, ULONGLONG Arg64, ULONG Arg32, Pointer Buffer,
			ULONG BufferSize, ULONGByReference InfoSize, byte[] StringBuffer,
			ULONG StringBufferSize, ULONGByReference StringSize);

	HRESULT GetSystemObjectInformation(ULONG Which, ULONGLONG Arg64, ULONG Arg32, Pointer Buffer,
			ULONG BufferSize, ULONGByReference InfoSize);
}
