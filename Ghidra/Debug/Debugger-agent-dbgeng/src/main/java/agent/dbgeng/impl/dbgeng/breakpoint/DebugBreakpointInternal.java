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
package agent.dbgeng.impl.dbgeng.breakpoint;

import java.util.List;
import java.util.Map;

import com.sun.jna.Pointer;

import agent.dbgeng.dbgeng.DebugBreakpoint;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.Preferred;
import agent.dbgeng.impl.dbgeng.control.DebugControlInternal;
import agent.dbgeng.jna.dbgeng.breakpoint.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugBreakpointInternal extends DebugBreakpoint {
	Map<Pointer, DebugBreakpointInternal> CACHE = new WeakValueHashMap<>();

	static DebugBreakpointInternal instanceFor(WrapIDebugBreakpoint bp) {
		return DbgEngUtil.lazyWeakCache(CACHE, bp, DebugBreakpointImpl1::new);
	}

	static DebugBreakpointInternal instanceFor(WrapIDebugBreakpoint2 bp) {
		return DbgEngUtil.lazyWeakCache(CACHE, bp, DebugBreakpointImpl2::new);
	}

	static DebugBreakpointInternal instanceFor(WrapIDebugBreakpoint3 bp) {
		return DbgEngUtil.lazyWeakCache(CACHE, bp, DebugBreakpointImpl3::new);
	}

	List<Preferred<WrapIDebugBreakpoint>> PREFERRED_BREAKPOINT_IIDS = List.of(
		new Preferred<>(IDebugBreakpoint3.IID_IDEBUG_BREAKPOINT3, WrapIDebugBreakpoint3.class),
		new Preferred<>(IDebugBreakpoint2.IID_IDEBUG_BREAKPOINT2, WrapIDebugBreakpoint2.class),
		new Preferred<>(IDebugBreakpoint.IID_IDEBUG_BREAKPOINT, WrapIDebugBreakpoint.class));

	static DebugBreakpointInternal tryPreferredInterfaces(DebugControlInternal control,
			InterfaceSupplier supplier) {
		DebugBreakpointInternal bpt = DbgEngUtil.tryPreferredInterfaces(
			DebugBreakpointInternal.class, PREFERRED_BREAKPOINT_IIDS, supplier);
		bpt.setControl(control);
		return bpt;
	}

	void setControl(DebugControlInternal control);
}
