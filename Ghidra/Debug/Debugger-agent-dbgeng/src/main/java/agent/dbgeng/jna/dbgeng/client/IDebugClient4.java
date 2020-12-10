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

import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugClient4 extends IDebugClient3 {
	final IID IID_IDEBUG_CLIENT4 = new IID("ca83c3de-5089-4cf8-93c8-d892387f2a5e");

	enum VTIndices4 implements VTableIndex {
		OPEN_DUMP_FILE_WIDE, //
		WRITE_DUMP_FILE_WIDE, //
		ADD_DUMP_INFORMATION_FILE_WIDE, //
		GET_NUMBER_DUMP_FILES, //
		GET_DUMP_FILE, //
		GET_DUMP_FILE_WIDE, //
		;

		static int start = VTableIndex.follow(VTIndices3.class);

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT OpenDumpFileWide(WString FileName, ULONGLONG FileHandle);

	HRESULT WriteDumpFileWide(WString FileName, ULONGLONG FileHandle, ULONG Qualifier,
			ULONG FormatFlags, WString Comment);

	HRESULT AddDumpInformationFileWide(WString FileName, ULONGLONG FileHandle, ULONG Type);

	HRESULT GetNumberDumpFiles(ULONGByReference Number);

	HRESULT GetDumpFile(ULONG Index, byte[] Buffer, ULONG BufferSize, ULONGByReference NameSize,
			ULONGLONGByReference Handle, ULONGByReference Type);

	HRESULT GetDumpFileWide(ULONG Index, char[] Buffer, ULONG BufferSize, ULONGByReference NameSize,
			ULONGLONGByReference Handle, ULONGByReference Type);
}
