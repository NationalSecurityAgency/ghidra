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
package agent.dbgmodel.impl.dbgmodel.datamodel;

import java.util.List;
import java.util.Map;

import com.sun.jna.Pointer;

import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.Preferred;
import agent.dbgmodel.dbgmodel.datamodel.DataModelManager1;
import agent.dbgmodel.jna.dbgmodel.datamodel.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DataModelManagerInternal extends DataModelManager1 {
	Map<Pointer, DataModelManagerInternal> CACHE = new WeakValueHashMap<>();

	static DataModelManagerInternal instanceFor(WrapIDataModelManager1 data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DataModelManagerImpl1::new);
	}

	static DataModelManagerInternal instanceFor(WrapIDataModelManager2 data) {
		return DbgEngUtil.lazyWeakCache(CACHE, data, DataModelManagerImpl2::new);
	}

	List<Preferred<WrapIDataModelManager1>> PREFERRED_DATA_SPACES_IIDS = List.of(
		new Preferred<>(IDataModelManager2.IID_IDATA_MODEL_MANAGER2, WrapIDataModelManager2.class),
		new Preferred<>(IDataModelManager1.IID_IDATA_MODEL_MANAGER, WrapIDataModelManager1.class));

	static DataModelManagerInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DataModelManagerInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
