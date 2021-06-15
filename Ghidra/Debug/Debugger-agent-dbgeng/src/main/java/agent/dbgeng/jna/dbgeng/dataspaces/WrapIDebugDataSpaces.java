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

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgeng.jna.dbgeng.UnknownWithUtils;
import agent.dbgeng.jna.dbgeng.sysobj.WrapIDebugSystemObjects;

public class WrapIDebugDataSpaces extends UnknownWithUtils implements IDebugDataSpaces {
	public static class ByReference extends WrapIDebugSystemObjects
			implements Structure.ByReference {
	}

	public WrapIDebugDataSpaces() {
	}

	public WrapIDebugDataSpaces(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT ReadVirtual(ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesRead) {
		return _invokeHR(VTIndices.READ_VIRTUAL, getPointer(), Offset, Buffer, BufferSize,
			BytesRead);
	}

	@Override
	public HRESULT WriteVirtual(ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesWritten) {
		return _invokeHR(VTIndices.WRITE_VIRTUAL, getPointer(), Offset, Buffer, BufferSize,
			BytesWritten);
	}

	@Override
	public HRESULT ReadVirtualUncached(ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesRead) {
		return _invokeHR(VTIndices.READ_VIRTUAL_UNCACHED, getPointer(), Offset, Buffer, BufferSize,
			BytesRead);
	}

	@Override
	public HRESULT WriteVirtualUncached(ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesWritten) {
		return _invokeHR(VTIndices.WRITE_VIRTUAL_UNCACHED, getPointer(), Offset, Buffer, BufferSize,
			BytesWritten);
	}

	@Override
	public HRESULT ReadPhysical(ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesRead) {
		return _invokeHR(VTIndices.READ_PHYSICAL, getPointer(), Offset, Buffer, BufferSize,
			BytesRead);
	}

	@Override
	public HRESULT WritePhysical(ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesWritten) {
		return _invokeHR(VTIndices.WRITE_PHYSICAL, getPointer(), Offset, Buffer, BufferSize,
			BytesWritten);
	}

	@Override
	public HRESULT ReadControl(ULONG Processor, ULONGLONG Offset, ByteBuffer Buffer,
			ULONG BufferSize, ULONGByReference BytesRead) {
		return _invokeHR(VTIndices.READ_CONTROL, getPointer(), Processor, Processor, Offset, Buffer,
			BufferSize, BytesRead);
	}

	@Override
	public HRESULT WriteControl(ULONG Processor, ULONGLONG Offset, ByteBuffer Buffer,
			ULONG BufferSize, ULONGByReference BytesWritten) {
		return _invokeHR(VTIndices.WRITE_CONTROL, getPointer(), Offset, Buffer, BufferSize,
			BytesWritten);
	}

	@Override
	public HRESULT ReadBusData(ULONG BusDataType, ULONG BusNumber, ULONG SlotNumber,
			ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize, ULONGByReference BytesRead) {
		return _invokeHR(VTIndices.READ_BUS_DATA, getPointer(), BusDataType, BusNumber, SlotNumber,
			Offset, Buffer, BufferSize, BytesRead);
	}

	@Override
	public HRESULT WriteBusData(ULONG BusDataType, ULONG BusNumber, ULONG SlotNumber,
			ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize, ULONGByReference BytesWritten) {
		return _invokeHR(VTIndices.WRITE_BUS_DATA, getPointer(), BusDataType, BusNumber, SlotNumber,
			Offset, Buffer, BufferSize, BytesWritten);
	}

	@Override
	public HRESULT ReadIo(ULONG InterfaceType, ULONG BusNumber, ULONG AddressSpace,
			ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize, ULONGByReference BytesRead) {
		return _invokeHR(VTIndices.READ_IO, getPointer(), InterfaceType, BusNumber, AddressSpace,
			Offset, Buffer, BufferSize, BytesRead);
	}

	@Override
	public HRESULT WriteIo(ULONG InterfaceType, ULONG BusNumber, ULONG AddressSpace,
			ULONGLONG Offset, ByteBuffer Buffer, ULONG BufferSize, ULONGByReference BytesWritten) {
		return _invokeHR(VTIndices.WRITE_IO, getPointer(), InterfaceType, BusNumber, AddressSpace,
			Offset, Buffer, BufferSize, BytesWritten);
	}

	@Override
	public HRESULT ReadMsr(ULONG Msr, ULONGLONGByReference Value) {
		return _invokeHR(VTIndices.READ_MSR, getPointer(), Msr, Value);
	}

	@Override
	public HRESULT WriteMsr(ULONG Msr, ULONGLONG Value) {
		return _invokeHR(VTIndices.WRITE_MSR, getPointer(), Msr, Value);
	}

	@Override
	public HRESULT ReadDebuggerData(ULONG Offset, ByteBuffer Buffer, ULONG BufferSize,
			ULONGByReference BytesRead) {
		return _invokeHR(VTIndices.READ_DEBUGGER_DATA, getPointer(), Offset, Buffer, BufferSize,
			BytesRead);
	}

}
