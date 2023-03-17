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
import agent.dbgmodel.dbgmodel.datamodel.script.DataModelScriptTemplateEnumerator;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.IDataModelScriptTemplateEnumerator;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.WrapIDataModelScriptTemplateEnumerator;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DataModelScriptTemplateEnumeratorInternal
		extends DataModelScriptTemplateEnumerator {
	Map<Pointer, DataModelScriptTemplateEnumeratorInternal> CACHE = new WeakValueHashMap<>();

	static DataModelScriptTemplateEnumeratorInternal instanceFor(
			WrapIDataModelScriptTemplateEnumerator data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DataModelScriptTemplateEnumeratorImpl::new);
	}

	List<Preferred<WrapIDataModelScriptTemplateEnumerator>> PREFERRED_DATA_SPACES_IIDS = List.of(
		new Preferred<>(
			IDataModelScriptTemplateEnumerator.IID_IDATA_MODEL_SCRIPT_TEMPLATE_ENUMERATOR,
			WrapIDataModelScriptTemplateEnumerator.class));

	static DataModelScriptTemplateEnumeratorInternal tryPreferredInterfaces(
			InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DataModelScriptTemplateEnumeratorInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
