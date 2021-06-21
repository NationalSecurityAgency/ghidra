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
package agent.dbgeng.jna.dbgeng.io;

import java.util.List;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

public class VTableIDebugOutputCallbacks extends Structure {
	public static class ByReference extends VTableIDebugOutputCallbacks
			implements Structure.ByReference {
	}

	public static final List<String> FIELDS = createFieldsOrder("QueryInterfaceCallback",
		"AddRefCallback", "ReleaseCallback", "OutputCallback");

	public QueryInterfaceCallback QueryInterfaceCallback;
	public AddRefCallback AddRefCallback;
	public ReleaseCallback ReleaseCallback;
	public OutputCallback OutputCallback;

	@Override
	public List<String> getFieldOrder() {
		return FIELDS;
	}

	public static interface QueryInterfaceCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, REFIID refid, PointerByReference ppvObject);
	}

	public static interface AddRefCallback extends StdCallLibrary.StdCallCallback {
		int invoke(Pointer thisPointer);
	}

	public static interface ReleaseCallback extends StdCallLibrary.StdCallCallback {
		int invoke(Pointer thisPointer);
	}

	public static interface OutputCallback extends StdCallLibrary.StdCallCallback {
		HRESULT invoke(Pointer thisPointer, ULONG Mask, String Text);
	}
}
