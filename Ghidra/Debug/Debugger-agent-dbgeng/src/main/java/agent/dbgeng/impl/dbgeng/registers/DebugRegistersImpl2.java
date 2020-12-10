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
package agent.dbgeng.impl.dbgeng.registers;

import com.sun.jna.platform.win32.WinDef.ULONG;

import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_VALUE;
import agent.dbgeng.jna.dbgeng.registers.IDebugRegisters2;

import com.sun.jna.platform.win32.COM.COMUtils;

public class DebugRegistersImpl2 extends DebugRegistersImpl1 {
	private final IDebugRegisters2 jnaRegisters;

	public DebugRegistersImpl2(IDebugRegisters2 jnaRegisters) {
		super(jnaRegisters);
		this.jnaRegisters = jnaRegisters;
	}

	@Override
	protected void doGetValues(DebugRegisterSource source, ULONG ulCount, ULONG[] pulIndices,
			DEBUG_VALUE[] pValues) {
		ULONG ulSource = new ULONG(source.ordinal());
		COMUtils
				.checkRC(
					jnaRegisters.GetValues2(ulSource, ulCount, pulIndices, new ULONG(0), pValues));
	}

	@Override
	protected void doSetValues(DebugRegisterSource source, ULONG ulCount, ULONG[] pulIndices,
			DEBUG_VALUE[] pValues) {
		ULONG ulSource = new ULONG(source.ordinal());
		COMUtils
				.checkRC(
					jnaRegisters.SetValues2(ulSource, ulCount, pulIndices, new ULONG(0), pValues));
	}
}
