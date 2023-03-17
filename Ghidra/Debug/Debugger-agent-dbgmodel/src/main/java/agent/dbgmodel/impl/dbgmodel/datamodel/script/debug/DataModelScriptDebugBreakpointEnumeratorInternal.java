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
package agent.dbgmodel.impl.dbgmodel.datamodel.script.debug;

import java.util.List;
import java.util.Map;

import com.sun.jna.Pointer;

import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.Preferred;
import agent.dbgmodel.dbgmodel.datamodel.script.debug.DataModelScriptDebugBreakpointEnumerator;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.debug.IDataModelScriptDebugBreakpointEnumerator;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.debug.WrapIDataModelScriptDebugBreakpointEnumerator;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DataModelScriptDebugBreakpointEnumeratorInternal
		extends DataModelScriptDebugBreakpointEnumerator {
	Map<Pointer, DataModelScriptDebugBreakpointEnumeratorInternal> CACHE = new WeakValueHashMap<>();

	static DataModelScriptDebugBreakpointEnumeratorInternal instanceFor(
			WrapIDataModelScriptDebugBreakpointEnumerator data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data,
			DataModelScriptDebugBreakpointEnumeratorImpl::new);
	}

	List<Preferred<WrapIDataModelScriptDebugBreakpointEnumerator>> PREFERRED_DATA_SPACES_IIDS =
		List.of(
			new Preferred<>(
				IDataModelScriptDebugBreakpointEnumerator.IID_IDATA_MODEL_SCRIPT_DEBUG_BREAKPOINT_ENUMERATOR,
				WrapIDataModelScriptDebugBreakpointEnumerator.class));

	static DataModelScriptDebugBreakpointEnumeratorInternal tryPreferredInterfaces(
			InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(
			DataModelScriptDebugBreakpointEnumeratorInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
