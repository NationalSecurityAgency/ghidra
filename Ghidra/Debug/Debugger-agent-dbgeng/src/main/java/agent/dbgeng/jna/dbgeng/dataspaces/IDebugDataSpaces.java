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
package agent.dbgeng.jna.dbgeng.dataspaces;

import java.nio.ByteBuffer;

import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.IUnknown;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils.VTableIndex;

public interface IDebugDataSpaces extends IUnknown {
	final IID IID_IDEBUG_DATA_SPACES = new IID("88f7dfab-3ea7-4c3a-aefb-c4e8106173aa");

	enum VTIndices implements VTableIndex {
		READ_VIRTUAL, //
		WRITE_VIRTUAL, //
		SEARCH_VIRTUAL, //
		READ_VIRTUAL_UNCACHED, //
		WRITE_VIRTUAL_UNCACHED, //
		READ_POINTERS_VIRTUAL, //
		WRITE_POINTERS_VIRTUAL, //
		READ_PHYSICAL, //
		WRITE_PHYSICAL, //
		READ_CONTROL, //
		WRITE_CONTROL, //
		READ_IO, //
		WRITE_IO, //
		READ_MSR, //
		WRITE_MSR, //
		READ_BUS_DATA, //
		WRITE_BUS_DATA, //
		CHECK_LOW_MEMORY, //
		READ_DEBUGGER_DATA, //
		READ_PROCESSOR_SYSTEM_DATA, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT ReadVirtual(ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesRead);

	HRESULT WriteVirtual(ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesWritten);

	HRESULT ReadVirtualUncached(ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesRead);

	HRESULT WriteVirtualUncached(ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesWritten);

	HRESULT ReadPhysical(ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesRead);

	HRESULT WritePhysical(ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesWritten);

	HRESULT ReadControl(ULONG Processor, ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesRead);

	HRESULT WriteControl(ULONG Processor, ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesWritten);

	HRESULT ReadBusData(ULONG BusDataType, ULONG BusNumber, ULONG SlotNumber, ULONGLONG Offset,
			ByteBuffer Buffer, ULONG BufferSize, ULONGByReference BytesRead);

	HRESULT WriteBusData(ULONG BusDataType, ULONG BusNumber, ULONG SlotNumber, ULONGLONG Offset,
			ByteBuffer Buffer, ULONG BufferSize, ULONGByReference BytesWritten);

	HRESULT ReadIo(ULONG InterfaceType, ULONG BusNumber, ULONG AddressSpace, ULONGLONG Offset,
			ByteBuffer Buffer, ULONG BufferSize, ULONGByReference BytesRead);

	HRESULT WriteIo(ULONG InterfaceType, ULONG BusNumber, ULONG AddressSpace, ULONGLONG Offset,
			ByteBuffer Buffer, ULONG BufferSize, ULONGByReference BytesWritten);

	HRESULT ReadMsr(ULONG Msr, ULONGLONGByReference Value);

	HRESULT WriteMsr(ULONG Msr, ULONGLONG Value);

	HRESULT ReadDebuggerData(ULONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesRead);

}
