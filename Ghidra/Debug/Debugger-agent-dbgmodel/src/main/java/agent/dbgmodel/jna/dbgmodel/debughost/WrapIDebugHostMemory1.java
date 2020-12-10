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
package agent.dbgmodel.jna.dbgmodel.debughost;

import java.nio.ByteBuffer;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;

public class WrapIDebugHostMemory1 extends UnknownWithUtils implements IDebugHostMemory1 {
	public static class ByReference extends WrapIDebugHostMemory1 implements Structure.ByReference {
	}

	public WrapIDebugHostMemory1() {
	}

	public WrapIDebugHostMemory1(Pointer pvInstance) {
		super(pvInstance);
	}

	@Override
	public HRESULT ReadBytes(Pointer context, LOCATION location, ByteBuffer buffer,
			ULONGLONG bufferSize,
			ULONGLONGByReference bytesRead) {
		return _invokeHR(VTIndices1.READ_BYTES, getPointer(), context, location, buffer, bufferSize,
			bytesRead);
	}

	@Override
	public HRESULT WriteBytes(Pointer context, LOCATION location, ByteBuffer buffer,
			ULONGLONG bufferSize,
			ULONGLONGByReference bytesWritten) {
		return _invokeHR(VTIndices1.WRITE_BYTES, getPointer(), context, location, buffer,
			bufferSize,
			bytesWritten);
	}

	@Override
	public HRESULT ReadPointers(Pointer context, LOCATION location, ULONGLONG count,
			ULONGLONGByReference pointers) {
		return _invokeHR(VTIndices1.READ_POINTERS, getPointer(), context, location, count,
			pointers);
	}

	@Override
	public HRESULT WritePointers(Pointer context, LOCATION location, ULONGLONG count,
			ULONGLONGByReference pointers) {
		return _invokeHR(VTIndices1.WRITE_POINTERS, getPointer(), context, location, count,
			pointers);
	}

	@Override
	public HRESULT GetDisplayStringForLocation(Pointer context, LOCATION location, BOOL verbose,
			BSTRByReference locationName) {
		return _invokeHR(VTIndices1.GET_DISPLAY_STRING_FOR_LOCATION, getPointer(), context,
			location,
			verbose, locationName);
	}

}
