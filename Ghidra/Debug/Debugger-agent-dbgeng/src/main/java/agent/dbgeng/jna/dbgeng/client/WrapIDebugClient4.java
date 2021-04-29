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
package agent.dbgeng.jna.dbgeng.client;

import com.sun.jna.*;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

/**
 * Wrapper class for the IDebugClient interface
 */
public class WrapIDebugClient4 extends WrapIDebugClient3 implements IDebugClient4 {
	public static class ByReference extends WrapIDebugClient4 implements Structure.ByReference {
	}

	public WrapIDebugClient4() {
	}

	public WrapIDebugClient4(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT OpenDumpFileWide(WString FileName, ULONGLONG FileHandle) {
		return _invokeHR(VTIndices4.OPEN_DUMP_FILE_WIDE, getPointer(), FileName, FileHandle);
	}

	@Override
	public HRESULT WriteDumpFileWide(WString FileName, ULONGLONG FileHandle, ULONG Qualifier,
			ULONG FormatFlags, WString Comment) {
		return _invokeHR(VTIndices4.WRITE_DUMP_FILE_WIDE, getPointer(), FileName, FileHandle,
			Qualifier, FormatFlags, Comment);
	}

	@Override
	public HRESULT AddDumpInformationFileWide(WString FileName, ULONGLONG FileHandle, ULONG Type) {
		return _invokeHR(VTIndices4.ADD_DUMP_INFORMATION_FILE_WIDE, getPointer(), FileName,
			FileHandle, Type);
	}

	@Override
	public HRESULT GetNumberDumpFiles(ULONGByReference Number) {
		return _invokeHR(VTIndices4.GET_NUMBER_DUMP_FILES, getPointer(), Number);
	}

	@Override
	public HRESULT GetDumpFile(ULONG Index, byte[] Buffer, ULONG BufferSize,
			ULONGByReference NameSize, ULONGLONGByReference Handle, ULONGByReference Type) {
		return _invokeHR(VTIndices4.GET_DUMP_FILE, getPointer(), Index, Buffer, BufferSize,
			NameSize, Handle, Type);
	}

	@Override
	public HRESULT GetDumpFileWide(ULONG Index, char[] Buffer, ULONG BufferSize,
			ULONGByReference NameSize, ULONGLONGByReference Handle, ULONGByReference Type) {
		return _invokeHR(VTIndices4.GET_DUMP_FILE_WIDE, getPointer(), Index, Buffer, BufferSize,
			NameSize, Handle, Type);
	}
}
