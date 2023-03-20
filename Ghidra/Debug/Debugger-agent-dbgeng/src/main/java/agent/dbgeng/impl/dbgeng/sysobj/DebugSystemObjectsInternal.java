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

import java.util.List;
import java.util.Map;

import com.sun.jna.Pointer;

import agent.dbgeng.dbgeng.DebugSystemObjects;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.Preferred;
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

	List<Preferred<WrapIDebugSystemObjects>> PREFERRED_SYSTEM_OBJECTS_IIDS = List.of(
		new Preferred<>(IDebugSystemObjects4.IID_IDEBUG_SYSTEM_OBJECTS4,
			WrapIDebugSystemObjects4.class),
		new Preferred<>(IDebugSystemObjects3.IID_IDEBUG_SYSTEM_OBJECTS3,
			WrapIDebugSystemObjects3.class),
		new Preferred<>(IDebugSystemObjects2.IID_IDEBUG_SYSTEM_OBJECTS2,
			WrapIDebugSystemObjects2.class),
		new Preferred<>(IDebugSystemObjects.IID_IDEBUG_SYSTEM_OBJECTS,
			WrapIDebugSystemObjects.class));

	static DebugSystemObjectsInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugSystemObjectsInternal.class,
			PREFERRED_SYSTEM_OBJECTS_IIDS, supplier);
	}
}
