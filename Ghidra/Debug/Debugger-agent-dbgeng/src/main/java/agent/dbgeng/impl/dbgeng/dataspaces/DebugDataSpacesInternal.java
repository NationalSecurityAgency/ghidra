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
package agent.dbgeng.impl.dbgeng.dataspaces;

import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;

import agent.dbgeng.dbgeng.DebugDataSpaces;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.jna.dbgeng.dataspaces.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugDataSpacesInternal extends DebugDataSpaces {
	Map<Pointer, DebugDataSpacesInternal> CACHE = new WeakValueHashMap<>();

	static DebugDataSpacesInternal instanceFor(WrapIDebugDataSpaces data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DebugDataSpacesImpl1::new);
	}

	static DebugDataSpacesInternal instanceFor(WrapIDebugDataSpaces2 data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DebugDataSpacesImpl2::new);
	}

	static DebugDataSpacesInternal instanceFor(WrapIDebugDataSpaces3 data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DebugDataSpacesImpl3::new);
	}

	static DebugDataSpacesInternal instanceFor(WrapIDebugDataSpaces4 data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DebugDataSpacesImpl4::new);
	}

	ImmutableMap.Builder<REFIID, Class<? extends WrapIDebugDataSpaces>> PREFERRED_DATA_SPACES_IIDS_BUILDER =
		ImmutableMap.builder();
	Map<REFIID, Class<? extends WrapIDebugDataSpaces>> PREFERRED_DATA_SPACES_IIDS =
		PREFERRED_DATA_SPACES_IIDS_BUILDER //
				.put(new REFIID(IDebugDataSpaces4.IID_IDEBUG_DATA_SPACES4),
					WrapIDebugDataSpaces4.class) //
				.put(new REFIID(IDebugDataSpaces3.IID_IDEBUG_DATA_SPACES3),
					WrapIDebugDataSpaces3.class) //
				.put(new REFIID(IDebugDataSpaces2.IID_IDEBUG_DATA_SPACES2),
					WrapIDebugDataSpaces2.class) //
				.put(new REFIID(IDebugDataSpaces.IID_IDEBUG_DATA_SPACES),
					WrapIDebugDataSpaces.class) //
				.build();

	static DebugDataSpacesInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugDataSpacesInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
