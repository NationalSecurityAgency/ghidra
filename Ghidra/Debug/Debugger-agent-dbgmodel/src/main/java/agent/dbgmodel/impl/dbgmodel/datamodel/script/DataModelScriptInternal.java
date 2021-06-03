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

import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;

import agent.dbgmodel.dbgmodel.datamodel.script.DataModelScript;
import agent.dbgmodel.impl.dbgmodel.DbgModelUtil;
import agent.dbgmodel.impl.dbgmodel.DbgModelUtil.InterfaceSupplier;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.IDataModelScript;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.WrapIDataModelScript;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DataModelScriptInternal extends DataModelScript {
	Map<Pointer, DataModelScriptInternal> CACHE = new WeakValueHashMap<>();

	static DataModelScriptInternal instanceFor(WrapIDataModelScript data) {
		return DbgModelUtil.lazyWeakCache(CACHE, data, DataModelScriptImpl::new);
	}

	ImmutableMap.Builder<REFIID, Class<? extends WrapIDataModelScript>> PREFERRED_DATA_SPACES_IIDS_BUILDER =
		ImmutableMap.builder();
	Map<REFIID, Class<? extends WrapIDataModelScript>> PREFERRED_DATA_SPACES_IIDS =
		PREFERRED_DATA_SPACES_IIDS_BUILDER //
				.put(new REFIID(IDataModelScript.IID_IDATA_MODEL_SCRIPT),
					WrapIDataModelScript.class) //
				.build();

	static DataModelScriptInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgModelUtil.tryPreferredInterfaces(DataModelScriptInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
