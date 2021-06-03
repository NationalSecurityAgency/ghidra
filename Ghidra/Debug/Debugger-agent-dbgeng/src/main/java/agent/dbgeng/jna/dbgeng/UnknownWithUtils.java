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
package agent.dbgeng.jna.dbgeng;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.Unknown;

public class UnknownWithUtils extends Unknown {
	public static interface VTableIndex {
		int getIndex();

		public static <I extends Enum<I> & VTableIndex> int follow(Class<I> prev) {
			I[] all = prev.getEnumConstants();
			int start = all[0].getIndex() - all[0].ordinal();
			return all.length + start;
		}
	}

	public UnknownWithUtils() {
	}

	public UnknownWithUtils(Pointer pvInstance) {
		super(pvInstance);
	}

	protected HRESULT _invokeHR(VTableIndex idx, Object... args) {
		/*if (idx != IDebugClient.VTIndices.DISPATCH_CALLBACKS &&
			idx != IDebugControl.VTIndices.GET_EXECUTION_STATUS) {
			Msg.info(this, Thread.currentThread() + " invoked " + idx + Arrays.asList(args));
		}*/
		return (HRESULT) this._invokeNativeObject(idx.getIndex(), args, HRESULT.class);
	}
}
