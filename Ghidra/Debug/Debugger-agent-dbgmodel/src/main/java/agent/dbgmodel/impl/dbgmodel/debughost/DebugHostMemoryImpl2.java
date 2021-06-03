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

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgmodel.dbgmodel.debughost.DebugHostContext;
import agent.dbgmodel.dbgmodel.debughost.DebugHostMemory2;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.LOCATION;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostMemory2;

public class DebugHostMemoryImpl2 extends DebugHostMemoryImpl1 implements DebugHostMemory2 {
	private final IDebugHostMemory2 jnaData;

	public DebugHostMemoryImpl2(IDebugHostMemory2 jnaData) {
		super(jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public LOCATION linearizeLocation(DebugHostContext context, LOCATION location) {
		Pointer pContext = context.getPointer();
		LOCATION.ByReference pLinearizedLocation = new LOCATION.ByReference();
		COMUtils.checkRC(jnaData.LinearizeLocation(pContext, location, pLinearizedLocation));
		return new LOCATION(pLinearizedLocation);
	}
}
