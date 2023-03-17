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
package agent.dbgmodel.impl.dbgmodel.datamodel.script;

import java.util.List;
import java.util.Map;

import com.sun.jna.Pointer;

import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.Preferred;
import agent.dbgmodel.dbgmodel.datamodel.script.DataModelScriptHostContext;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.IDataModelScriptHostContext;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.WrapIDataModelScriptHostContext;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DataModelScriptHostContextInternal extends DataModelScriptHostContext {
	Map<Pointer, DataModelScriptHostContextInternal> CACHE = new WeakValueHashMap<>();

	static DataModelScriptHostContextInternal instanceFor(WrapIDataModelScriptHostContext data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DataModelScriptHostContextImpl::new);
	}

	List<Preferred<WrapIDataModelScriptHostContext>> PREFERRED_DATA_SPACES_IIDS = List.of(
		new Preferred<>(IDataModelScriptHostContext.IID_IDATA_MODEL_SCRIPT_HOST_CONTEXT,
			WrapIDataModelScriptHostContext.class));

	static DataModelScriptHostContextInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DataModelScriptHostContextInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
