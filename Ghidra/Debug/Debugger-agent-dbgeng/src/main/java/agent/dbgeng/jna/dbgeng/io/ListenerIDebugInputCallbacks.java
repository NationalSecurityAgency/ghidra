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

import com.sun.jna.Structure;
import com.sun.jna.platform.win32.WinDef.ULONG;
import com.sun.jna.platform.win32.WinNT.HRESULT;

public class ListenerIDebugInputCallbacks extends Structure
		implements IDebugInputCallbacks, MarkerInputCallbacks {
	public static final List<String> FIELDS = createFieldsOrder("vtbl");

	public ListenerIDebugInputCallbacks(CallbackIDebugInputCallbacks callback) {
		this.vtbl = this.constructVTable();
		this.initVTable(callback);
		super.write();
	}

	public VTableIDebugInputCallbacks.ByReference vtbl;

	@Override
	protected List<String> getFieldOrder() {
		return FIELDS;
	}

	protected VTableIDebugInputCallbacks.ByReference constructVTable() {
		return new VTableIDebugInputCallbacks.ByReference();
	}

	protected void initVTable(final CallbackIDebugInputCallbacks callback) {
		vtbl.QueryInterfaceCallback = (thisPointer, refid, ppvObject) -> {
			return callback.QueryInterface(refid, ppvObject);
		};
		vtbl.AddRefCallback = (thisPointer) -> {
			return callback.AddRef();
		};
		vtbl.ReleaseCallback = (thisPointer) -> {
			return callback.Release();
		};
		vtbl.StartInputCallback = (thisPointer, BufferSize) -> {
			return callback.StartInput(BufferSize);
		};
		vtbl.EndInputCallback = (thisPointer) -> {
			return callback.EndInput();
		};
	}

	@Override
	public HRESULT StartInput(ULONG BufferSize) {
		return this.vtbl.StartInputCallback.invoke(getPointer(), BufferSize);
	}

	@Override
	public HRESULT EndInput() {
		return this.vtbl.EndInputCallback.invoke(getPointer());
	}
}
