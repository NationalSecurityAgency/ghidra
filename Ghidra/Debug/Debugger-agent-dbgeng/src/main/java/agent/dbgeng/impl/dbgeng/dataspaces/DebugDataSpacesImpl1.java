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
package agent.dbgeng.impl.dbgeng.dataspaces;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import javax.help.UnsupportedOperationException;

import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgeng.dbgeng.COMUtilsExtra;
import agent.dbgeng.dbgeng.DbgEng;
import agent.dbgeng.dbgeng.DbgEng.OpaqueCleanable;
import agent.dbgeng.jna.dbgeng.dataspaces.IDebugDataSpaces;

public class DebugDataSpacesImpl1 implements DebugDataSpacesInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanble;
	private final IDebugDataSpaces jnaData;

	public DebugDataSpacesImpl1(IDebugDataSpaces jnaData) {
		this.cleanble = DbgEng.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public DebugMemoryBasicInformation queryVirtual(long offset) {
		throw new UnsupportedOperationException("Not implemented in this interface");
	}

	@Override
	public int readVirtual(long offset, ByteBuffer into, int len) {
		if (len > into.remaining()) {
			throw new BufferOverflowException();
		}
		ULONGLONG ullOffset = new ULONGLONG(offset);
		ULONG ulLen = new ULONG(len);
		ULONGByReference pulBytesRead = new ULONGByReference();
		HRESULT hr = jnaData.ReadVirtual(ullOffset, into, ulLen, pulBytesRead);
		if (hr.equals(COMUtilsExtra.E_CANNOT_READ)) {
			return 0;
		}
		COMUtils.checkRC(hr);
		int read = pulBytesRead.getValue().intValue();
		into.position(read + into.position());
		return read;
	}

	@Override
	public int writeVirtual(long offset, ByteBuffer from, int len) {
		if (len > from.remaining()) {
			throw new BufferOverflowException();
		}
		ULONGLONG ullOffset = new ULONGLONG(offset);
		ULONG ulLen = new ULONG(len);
		ULONGByReference pulBytesWritten = new ULONGByReference();
		COMUtils.checkRC(jnaData.WriteVirtual(ullOffset, from, ulLen, pulBytesWritten));
		int written = pulBytesWritten.getValue().intValue();
		from.position(written + from.position());
		return written;
	}

	@Override
	public int readVirtualUncached(long offset, ByteBuffer into, int len) {
		if (len > into.remaining()) {
			throw new BufferOverflowException();
		}
		ULONGLONG ullOffset = new ULONGLONG(offset);
		ULONG ulLen = new ULONG(len);
		ULONGByReference pulBytesRead = new ULONGByReference();
		COMUtils.checkRC(jnaData.ReadVirtualUncached(ullOffset, into, ulLen, pulBytesRead));
		int read = pulBytesRead.getValue().intValue();
		into.position(read + into.position());
		return read;
	}

	@Override
	public int writeVirtualUncached(long offset, ByteBuffer from, int len) {
		if (len > from.remaining()) {
			throw new BufferOverflowException();
		}
		ULONGLONG ullOffset = new ULONGLONG(offset);
		ULONG ulLen = new ULONG(len);
		ULONGByReference pulBytesWritten = new ULONGByReference();
		COMUtils.checkRC(jnaData.WriteVirtualUncached(ullOffset, from, ulLen, pulBytesWritten));
		int written = pulBytesWritten.getValue().intValue();
		from.position(written + from.position());
		return written;
	}

	@Override
	public int readPhysical(long offset, ByteBuffer into, int len) {
		if (len > into.remaining()) {
			throw new BufferOverflowException();
		}
		ULONGLONG ullOffset = new ULONGLONG(offset);
		ULONG ulLen = new ULONG(len);
		ULONGByReference pulBytesRead = new ULONGByReference();
		COMUtils.checkRC(jnaData.ReadPhysical(ullOffset, into, ulLen, pulBytesRead));
		int read = pulBytesRead.getValue().intValue();
		into.position(read + into.position());
		return read;
	}

	@Override
	public int writePhysical(long offset, ByteBuffer from, int len) {
		if (len > from.remaining()) {
			throw new BufferOverflowException();
		}
		ULONGLONG ullOffset = new ULONGLONG(offset);
		ULONG ulLen = new ULONG(len);
		ULONGByReference pulBytesWritten = new ULONGByReference();
		COMUtils.checkRC(jnaData.WritePhysical(ullOffset, from, ulLen, pulBytesWritten));
		int written = pulBytesWritten.getValue().intValue();
		from.position(written + from.position());
		return written;
	}

	@Override
	public int readControl(int processor, long offset, ByteBuffer into, int len) {
		if (len > into.remaining()) {
			throw new BufferOverflowException();
		}
		ULONG ulProcessor = new ULONG(processor);
		ULONGLONG ullOffset = new ULONGLONG(offset);
		ULONG ulLen = new ULONG(len);
		ULONGByReference pulBytesRead = new ULONGByReference();
		COMUtils.checkRC(jnaData.ReadControl(ulProcessor, ullOffset, into, ulLen, pulBytesRead));
		int read = pulBytesRead.getValue().intValue();
		into.position(read + into.position());
		return read;
	}

	@Override
	public int writeControl(int processor, long offset, ByteBuffer from, int len) {
		if (len > from.remaining()) {
			throw new BufferOverflowException();
		}
		ULONG ulProcessor = new ULONG(processor);
		ULONGLONG ullOffset = new ULONGLONG(offset);
		ULONG ulLen = new ULONG(len);
		ULONGByReference pulBytesWritten = new ULONGByReference();
		COMUtils.checkRC(
			jnaData.WriteControl(ulProcessor, ullOffset, from, ulLen, pulBytesWritten));
		int written = pulBytesWritten.getValue().intValue();
		from.position(written + from.position());
		return written;
	}

	@Override
	public int readBusData(int busDataType, int busNumber, int slotNumber, long offset,
			ByteBuffer into, int len) {
		if (len > into.remaining()) {
			throw new BufferOverflowException();
		}
		ULONG ulBusDataType = new ULONG(busDataType);
		ULONG ulBusNumber = new ULONG(busNumber);
		ULONG ulSlotNumber = new ULONG(slotNumber);
		ULONGLONG ullOffset = new ULONGLONG(offset);
		ULONG ulLen = new ULONG(len);
		ULONGByReference pulBytesRead = new ULONGByReference();
		COMUtils.checkRC(jnaData.ReadBusData(ulBusDataType, ulBusNumber, ulSlotNumber, ullOffset,
			into, ulLen, pulBytesRead));
		int read = pulBytesRead.getValue().intValue();
		into.position(read + into.position());
		return read;
	}

	@Override
	public int writeBusData(int busDataType, int busNumber, int slotNumber, long offset,
			ByteBuffer from, int len) {
		if (len > from.remaining()) {
			throw new BufferOverflowException();
		}
		ULONG ulBusDataType = new ULONG(busDataType);
		ULONG ulBusNumber = new ULONG(busNumber);
		ULONG ulSlotNumber = new ULONG(slotNumber);
		ULONGLONG ullOffset = new ULONGLONG(offset);
		ULONG ulLen = new ULONG(len);
		ULONGByReference pulBytesWritten = new ULONGByReference();
		COMUtils.checkRC(jnaData.WriteBusData(ulBusDataType, ulBusNumber, ulSlotNumber, ullOffset,
			from, ulLen, pulBytesWritten));
		int written = pulBytesWritten.getValue().intValue();
		from.position(written + from.position());
		return written;
	}

	@Override
	public int readIo(int interfaceType, int busNumber, int addressSpace, long offset,
			ByteBuffer into, int len) {
		if (len > into.remaining()) {
			throw new BufferOverflowException();
		}
		ULONG ulInterfaceType = new ULONG(interfaceType);
		ULONG ulBusNumber = new ULONG(busNumber);
		ULONG ulAddressSpace = new ULONG(addressSpace);
		ULONGLONG ullOffset = new ULONGLONG(offset);
		ULONG ulLen = new ULONG(len);
		ULONGByReference pulBytesRead = new ULONGByReference();
		COMUtils.checkRC(jnaData.ReadIo(ulInterfaceType, ulBusNumber, ulAddressSpace, ullOffset,
			into, ulLen, pulBytesRead));
		int read = pulBytesRead.getValue().intValue();
		into.position(read + into.position());
		return read;
	}

	@Override
	public int writeIo(int interfaceType, int busNumber, int addressSpace, long offset,
			ByteBuffer from, int len) {
		if (len > from.remaining()) {
			throw new BufferOverflowException();
		}
		ULONG ulInterfaceType = new ULONG(interfaceType);
		ULONG ulBusNumber = new ULONG(busNumber);
		ULONG ulAddressSpace = new ULONG(addressSpace);
		ULONGLONG ullOffset = new ULONGLONG(offset);
		ULONG ulLen = new ULONG(len);
		ULONGByReference pulBytesWritten = new ULONGByReference();
		COMUtils.checkRC(jnaData.WriteIo(ulInterfaceType, ulBusNumber, ulAddressSpace, ullOffset,
			from, ulLen, pulBytesWritten));
		int written = pulBytesWritten.getValue().intValue();
		from.position(written + from.position());
		return written;
	}

	@Override
	public long readMsr(int msr) {
		ULONG ulNumber = new ULONG(msr);
		ULONGLONGByReference pulValue = new ULONGLONGByReference();
		COMUtils.checkRC(jnaData.ReadMsr(ulNumber, pulValue));
		return pulValue.getValue().longValue();
	}

	@Override
	public void writeMsr(int msr, long value) {
		ULONG ulNumber = new ULONG(msr);
		ULONGLONG ullValue = new ULONGLONG(value);
		COMUtils.checkRC(jnaData.WriteMsr(ulNumber, ullValue));
	}

	@Override
	public int readDebuggerData(int offset, ByteBuffer into, int len) {
		if (len > into.remaining()) {
			throw new BufferOverflowException();
		}
		ULONG ulOffset = new ULONG(offset);
		ULONG ulLen = new ULONG(len);
		ULONGByReference pulBytesRead = new ULONGByReference();
		COMUtils.checkRC(jnaData.ReadDebuggerData(ulOffset, into, ulLen, pulBytesRead));
		int read = pulBytesRead.getValue().intValue();
		into.position(read + into.position());
		return read;
	}

}
