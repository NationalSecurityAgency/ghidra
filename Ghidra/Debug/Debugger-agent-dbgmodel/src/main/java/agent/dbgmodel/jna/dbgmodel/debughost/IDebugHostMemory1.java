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
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WTypes.BSTRByReference;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.UnknownWithUtils.VTableIndex;

public interface IDebugHostMemory1 extends IUnknownEx {
	final IID IID_IDEBUG_HOST_MEMORY = new IID("212149C9-9183-4a3e-B00E-4FD1DC95339B");

	enum VTIndices1 implements VTableIndex {
		READ_BYTES, //
		WRITE_BYTES, //
		READ_POINTERS, //
		WRITE_POINTERS, //
		GET_DISPLAY_STRING_FOR_LOCATION, //
		;

		static int start = 3;

		@Override
		public int getIndex() {
			return this.ordinal() + start;
		}
	}

	HRESULT ReadBytes(Pointer context, LOCATION location, ByteBuffer buffer, ULONGLONG bufferSize,
			ULONGLONGByReference bytesRead);

	HRESULT WriteBytes(Pointer context, LOCATION location, ByteBuffer buffer, ULONGLONG bufferSize,
			ULONGLONGByReference bytesWritten);

	HRESULT ReadPointers(Pointer context, LOCATION location, ULONGLONG count,
			ULONGLONGByReference pointers);

	HRESULT WritePointers(Pointer context, LOCATION location, ULONGLONG count,
			ULONGLONGByReference pointers);

	HRESULT GetDisplayStringForLocation(Pointer context, LOCATION location, BOOL verbose,
			BSTRByReference locationName);

}
