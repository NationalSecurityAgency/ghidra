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

import java.util.Map;

import com.google.common.collect.ImmutableMap;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Guid.REFIID;

import agent.dbgmodel.dbgmodel.datamodel.DataModelManager1;
import agent.dbgmodel.impl.dbgmodel.DbgModelUtil;
import agent.dbgmodel.impl.dbgmodel.DbgModelUtil.InterfaceSupplier;
import agent.dbgmodel.jna.dbgmodel.datamodel.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DataModelManagerInternal extends DataModelManager1 {
	Map<Pointer, DataModelManagerInternal> CACHE = new WeakValueHashMap<>();

	static DataModelManagerInternal instanceFor(WrapIDataModelManager1 data) {
		return DbgModelUtil.lazyWeakCache(CACHE, data, DataModelManagerImpl1::new);
	}

	static DataModelManagerInternal instanceFor(WrapIDataModelManager2 data) {
		return DbgModelUtil.lazyWeakCache(CACHE, data, DataModelManagerImpl2::new);
	}

	ImmutableMap.Builder<REFIID, Class<? extends WrapIDataModelManager1>> PREFERRED_DATA_SPACES_IIDS_BUILDER =
		ImmutableMap.builder();
	Map<REFIID, Class<? extends WrapIDataModelManager1>> PREFERRED_DATA_SPACES_IIDS =
		PREFERRED_DATA_SPACES_IIDS_BUILDER //
				.put(new REFIID(IDataModelManager2.IID_IDATA_MODEL_MANAGER2),
					WrapIDataModelManager2.class) //
				.put(new REFIID(IDataModelManager1.IID_IDATA_MODEL_MANAGER),
					WrapIDataModelManager1.class) //
				.build();

	static DataModelManagerInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgModelUtil.tryPreferredInterfaces(DataModelManagerInternal.class,
			PREFERRED_DATA_SPACES_IIDS, supplier);
	}
}
