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
package agent.dbgeng.impl.dbgeng.control;

import java.util.List;
import java.util.Map;

import com.sun.jna.Pointer;

import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.Preferred;
import agent.dbgeng.jna.dbgeng.breakpoint.IDebugBreakpoint;
import agent.dbgeng.jna.dbgeng.control.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugControlInternal extends DebugControl {
	Map<Pointer, DebugControlInternal> CACHE = new WeakValueHashMap<>();

	static DebugControlInternal instanceFor(WrapIDebugControl control) {
		return DbgEngUtil.lazyWeakCache(CACHE, control, DebugControlImpl1::new);
	}

	static DebugControlInternal instanceFor(WrapIDebugControl2 control) {
		return DbgEngUtil.lazyWeakCache(CACHE, control, DebugControlImpl2::new);
	}

	static DebugControlInternal instanceFor(WrapIDebugControl3 control) {
		return DbgEngUtil.lazyWeakCache(CACHE, control, DebugControlImpl3::new);
	}

	static DebugControlInternal instanceFor(WrapIDebugControl4 control) {
		return DbgEngUtil.lazyWeakCache(CACHE, control, DebugControlImpl4::new);
	}

	static DebugControlInternal instanceFor(WrapIDebugControl5 control) {
		return DbgEngUtil.lazyWeakCache(CACHE, control, DebugControlImpl5::new);
	}

	static DebugControlInternal instanceFor(WrapIDebugControl6 control) {
		return DbgEngUtil.lazyWeakCache(CACHE, control, DebugControlImpl6::new);
	}

	static DebugControlInternal instanceFor(WrapIDebugControl7 control) {
		return DbgEngUtil.lazyWeakCache(CACHE, control, DebugControlImpl7::new);
	}

	List<Preferred<WrapIDebugControl>> PREFERRED_CONTROL_IIDS = List.of(
		new Preferred<>(IDebugControl7.IID_IDEBUG_CONTROL7, WrapIDebugControl7.class),
		new Preferred<>(IDebugControl6.IID_IDEBUG_CONTROL6, WrapIDebugControl6.class),
		new Preferred<>(IDebugControl5.IID_IDEBUG_CONTROL5, WrapIDebugControl5.class),
		new Preferred<>(IDebugControl4.IID_IDEBUG_CONTROL4, WrapIDebugControl4.class),
		new Preferred<>(IDebugControl3.IID_IDEBUG_CONTROL3, WrapIDebugControl3.class),
		new Preferred<>(IDebugControl2.IID_IDEBUG_CONTROL2, WrapIDebugControl2.class),
		new Preferred<>(IDebugControl.IID_IDEBUG_CONTROL, WrapIDebugControl.class));

	static DebugControlInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugControlInternal.class, PREFERRED_CONTROL_IIDS,
			supplier);
	}

	void removeBreakpoint(IDebugBreakpoint comBpt);
}
