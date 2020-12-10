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
package agent.dbgmodel.impl.dbgmodel.datamodel.script.debug;

import com.sun.jna.Pointer;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.debug.IDataModelScriptDebugStackFrame;

public class DataModelScriptDebugStackFrameImpl implements DataModelScriptDebugStackFrameInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDataModelScriptDebugStackFrame jnaData;

	public DataModelScriptDebugStackFrameImpl(IDataModelScriptDebugStackFrame jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	/*
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
		COMUtils.checkRC(jnaData.ReadVirtual(ullOffset, into, ulLen, pulBytesRead));
		int read = pulBytesRead.getValue().intValue();
		into.position(read + into.position());
		return read;
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
	*/
}
