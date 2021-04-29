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
package agent.dbgeng.impl.dbgeng.sysobj;

import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;

import agent.dbgeng.dbgeng.DebugSystemObjects;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.jna.dbgeng.sysobj.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugSystemObjectsInternal extends DebugSystemObjects {
	Map<Pointer, DebugSystemObjectsInternal> CACHE = new WeakValueHashMap<>();

	static DebugSystemObjectsInternal instanceFor(WrapIDebugSystemObjects sysobj) {
		return DbgEngUtil.lazyWeakCache(CACHE, sysobj, DebugSystemObjectsImpl1::new);
	}

	static DebugSystemObjectsInternal instanceFor(WrapIDebugSystemObjects2 sysobj) {
		return DbgEngUtil.lazyWeakCache(CACHE, sysobj, DebugSystemObjectsImpl2::new);
	}

	static DebugSystemObjectsInternal instanceFor(WrapIDebugSystemObjects3 sysobj) {
		return DbgEngUtil.lazyWeakCache(CACHE, sysobj, DebugSystemObjectsImpl3::new);
	}

	static DebugSystemObjectsInternal instanceFor(WrapIDebugSystemObjects4 sysobj) {
		return DbgEngUtil.lazyWeakCache(CACHE, sysobj, DebugSystemObjectsImpl4::new);
	}

	ImmutableMap.Builder<REFIID, Class<? extends WrapIDebugSystemObjects>> PREFERRED_SYSTEM_OBJECTS_IIDS_BUILDER =
		ImmutableMap.builder();
	Map<REFIID, Class<? extends WrapIDebugSystemObjects>> PREFERRED_SYSTEM_OBJECTS_IIDS =
		PREFERRED_SYSTEM_OBJECTS_IIDS_BUILDER //
				.put(new REFIID(IDebugSystemObjects4.IID_IDEBUG_SYSTEM_OBJECTS4),
					WrapIDebugSystemObjects4.class) //
				.put(new REFIID(IDebugSystemObjects3.IID_IDEBUG_SYSTEM_OBJECTS3),
					WrapIDebugSystemObjects3.class) //
				.put(new REFIID(IDebugSystemObjects2.IID_IDEBUG_SYSTEM_OBJECTS2),
					WrapIDebugSystemObjects2.class) //
				.put(new REFIID(IDebugSystemObjects.IID_IDEBUG_SYSTEM_OBJECTS),
					WrapIDebugSystemObjects.class) //
				.build();

	static DebugSystemObjectsInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugSystemObjectsInternal.class,
			PREFERRED_SYSTEM_OBJECTS_IIDS, supplier);
	}
}
