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

import agent.dbgmodel.dbgmodel.debughost.DebugHostConstant;
import agent.dbgmodel.impl.dbgmodel.DbgModelUtil;
import agent.dbgmodel.impl.dbgmodel.DbgModelUtil.InterfaceSupplier;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHostConstant;
import agent.dbgmodel.jna.dbgmodel.debughost.WrapIDebugHostConstant;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugHostConstantInternal extends DebugHostConstant {
	Map<Pointer, DebugHostConstantInternal> CACHE = new WeakValueHashMap<>();

	static DebugHostConstantInternal instanceFor(WrapIDebugHostConstant data) {
		return DbgModelUtil.lazyWeakCache(CACHE, data, DebugHostConstantImpl::new);
	}

	ImmutableMap.Builder<REFIID, Class<? extends WrapIDebugHostConstant>> PREFERRED_DATA_SPACES_IIDS_BUILDER =
		ImmutableMap.builder();
	Map<REFIID, Class<? extends WrapIDebugHostConstant>> PREFERRED_DATA_SPACES_IIDS =
		PREFERRED_DATA_SPACES_IIDS_BUILDER //
				.put(new REFIID(IDebugHostConstant.IID_IDEBUG_HOST_CONSTANT),
					WrapIDebugHostConstant.class) //
				.build();

	static DebugHostConstantInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgModelUtil.tryPreferredInterfaces(DebugHostConstantInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
