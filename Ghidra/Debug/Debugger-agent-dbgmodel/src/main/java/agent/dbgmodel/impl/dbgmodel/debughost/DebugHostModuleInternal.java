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

import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;

import agent.dbgmodel.dbgmodel.debughost.DebugHostModule1;
import agent.dbgmodel.impl.dbgmodel.DbgModelUtil;
import agent.dbgmodel.impl.dbgmodel.DbgModelUtil.InterfaceSupplier;
import agent.dbgmodel.jna.dbgmodel.debughost.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugHostModuleInternal extends DebugHostModule1 {
	Map<Pointer, DebugHostModuleInternal> CACHE = new WeakValueHashMap<>();

	static DebugHostModuleInternal instanceFor(WrapIDebugHostModule1 data) {
		return DbgModelUtil.lazyWeakCache(CACHE, data, DebugHostModuleImpl1::new);
	}

	static DebugHostModuleInternal instanceFor(WrapIDebugHostModule2 data) {
		return DbgModelUtil.lazyWeakCache(CACHE, data, DebugHostModuleImpl2::new);
	}

	ImmutableMap.Builder<REFIID, Class<? extends WrapIDebugHostModule1>> PREFERRED_DATA_SPACES_IIDS_BUILDER =
		ImmutableMap.builder();
	Map<REFIID, Class<? extends WrapIDebugHostModule1>> PREFERRED_DATA_SPACES_IIDS =
		PREFERRED_DATA_SPACES_IIDS_BUILDER //
				.put(new REFIID(IDebugHostModule2.IID_IDEBUG_HOST_MODULE2),
					WrapIDebugHostModule2.class) //
				.put(new REFIID(IDebugHostModule1.IID_IDEBUG_HOST_MODULE),
					WrapIDebugHostModule1.class) //
				.build();

	static DebugHostModuleInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgModelUtil.tryPreferredInterfaces(DebugHostModuleInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
