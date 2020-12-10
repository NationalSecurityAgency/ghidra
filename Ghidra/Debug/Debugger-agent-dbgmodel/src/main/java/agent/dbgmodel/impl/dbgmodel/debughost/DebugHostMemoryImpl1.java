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
package agent.dbgmodel.impl.dbgmodel.debughost;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.OleAuto;
import com.sun.jna.platform.win32.WTypes.BSTR;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.debughost.DebugHostContext;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostMemory1;

public class DebugHostMemoryImpl1 implements DebugHostMemoryInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugHostMemory1 jnaData;

	public DebugHostMemoryImpl1(IDebugHostMemory1 jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public long readBytes(DebugHostContext context, LOCATION location, ByteBuffer buffer,
			long bufferSize) {
		if (bufferSize > buffer.remaining()) {
			throw new BufferOverflowException();
		}
		Pointer pContext = context.getPointer();
		ULONGLONG pulBufferSize = new ULONGLONG(bufferSize);
		ULONGLONGByReference pulBytesRead = new ULONGLONGByReference();
		COMUtils.checkRC(
			jnaData.ReadBytes(pContext, location, buffer, pulBufferSize, pulBytesRead));
		long read = pulBytesRead.getValue().longValue();
		buffer.position((int) (read + buffer.position()));
		return read;
	}

	@Override
	public long writeBytes(DebugHostContext context, LOCATION location, ByteBuffer buffer,
			long bufferSize) {
		if (bufferSize > buffer.remaining()) {
			throw new BufferOverflowException();
		}
		Pointer pContext = context.getPointer();
		ULONGLONG pulBufferSize = new ULONGLONG(bufferSize);
		ULONGLONGByReference pulBytesWritten = new ULONGLONGByReference();
		COMUtils.checkRC(
			jnaData.WriteBytes(pContext, location, buffer, pulBufferSize, pulBytesWritten));
		long written = pulBytesWritten.getValue().longValue();
		buffer.position((int) (written + buffer.position()));
		return written;
	}

	@Override
	public ULONGLONGByReference readPointers(DebugHostContext context, LOCATION location,
			long count) {
		Pointer pContext = context.getPointer();
		ULONGLONG pCount = new ULONGLONG(count);
		ULONGLONGByReference pPointers = new ULONGLONGByReference();
		COMUtils.checkRC(jnaData.ReadPointers(pContext, location, pCount, pPointers));
		return pPointers;
	}

	@Override
	public ULONGLONGByReference writePointers(DebugHostContext context, LOCATION location,
			long count) {
		Pointer pContext = context.getPointer();
		ULONGLONG pCount = new ULONGLONG(count);
		ULONGLONGByReference pPointers = new ULONGLONGByReference();
		COMUtils.checkRC(jnaData.WritePointers(pContext, location, pCount, pPointers));
		return pPointers;
	}

	@Override
	public String GetDisplayStringForLocation(DebugHostContext context, LOCATION location,
			boolean verbose) {
		Pointer pContext = context.getPointer();
		BOOL bVerbose = new BOOL(verbose);
		BSTRByReference bref = new BSTRByReference();
		COMUtils.checkRC(
			jnaData.GetDisplayStringForLocation(pContext, location, bVerbose, bref));
		BSTR bstr = bref.getValue();
		String locationName = bstr.getValue();
		OleAuto.INSTANCE.SysFreeString(bstr);
		return locationName;
	}
}
