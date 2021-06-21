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

import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.IID;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;

public interface IDebugOutputCallbacks2 extends IDebugOutputCallbacks {
	final IID IID_IDEBUG_OUTPUT_CALLBACKS2 = new IID("67721fe9-56d2-4a44-a325-2b65513ce6eb");

	HRESULT GetInterestMask(ULONGByReference Mask);

	HRESULT Output2(ULONG Which, ULONG Flags, ULONGLONG Arg, WString Text);
}
