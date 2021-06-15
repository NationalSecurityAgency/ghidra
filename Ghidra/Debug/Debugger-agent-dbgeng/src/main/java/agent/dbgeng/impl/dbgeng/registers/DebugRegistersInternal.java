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

import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;

import agent.dbgeng.dbgeng.DebugRegisters;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.jna.dbgeng.registers.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugRegistersInternal extends DebugRegisters {
	Map<Pointer, DebugRegistersInternal> CACHE = new WeakValueHashMap<>();

	static DebugRegistersInternal instanceFor(WrapIDebugRegisters registers) {
		return DbgEngUtil.lazyWeakCache(CACHE, registers, DebugRegistersImpl1::new);
	}

	static DebugRegistersInternal instanceFor(WrapIDebugRegisters2 registers) {
		return DbgEngUtil.lazyWeakCache(CACHE, registers, DebugRegistersImpl2::new);
	}

	ImmutableMap.Builder<REFIID, Class<? extends WrapIDebugRegisters>> PREFERRED_REGISTERS_IIDS_BUILDER =
		ImmutableMap.builder();
	Map<REFIID, Class<? extends WrapIDebugRegisters>> PREFERRED_REGISTERS_IIDS =
		PREFERRED_REGISTERS_IIDS_BUILDER // 
				.put(new REFIID(IDebugRegisters2.IID_IDEBUG_REGISTERS2), WrapIDebugRegisters2.class) //
				.put(new REFIID(IDebugRegisters.IID_IDEBUG_REGISTERS), WrapIDebugRegisters.class) //
				.build();

	static DebugRegistersInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugRegistersInternal.class,
			PREFERRED_REGISTERS_IIDS, supplier);
	}
}
