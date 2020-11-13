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
package docking.widgets.table.threaded;

import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.task.TaskMonitor;

/**
 * A version of {@link ThreadedTableModel} for clients that do not need a DATA_SOURCE.  
 * <p>
 * <b>
 * Note: this class will change a <code>null</code> value for the {@link ServiceProvider} parameter
 * to a stubbed version.  If your model needs a real service provider, then you can pass a 
 * non-null value.
 * </b>
 *
 * @param <ROW_OBJECT> the row object class for this table model.
 */
public abstract class ThreadedTableModelStub<ROW_OBJECT> extends
		ThreadedTableModel<ROW_OBJECT, Object> {

	private static final ServiceProvider validateServiceProvider(ServiceProvider serviceProvider) {
		if (serviceProvider != null) {
			return serviceProvider;
		}
		return new ServiceProviderStub();
	}

	public ThreadedTableModelStub(String modelName, ServiceProvider serviceProvider) {
		this(modelName, serviceProvider, null);
	}

	public ThreadedTableModelStub(String modelName, ServiceProvider serviceProvider,
			TaskMonitor monitor) {
		this(modelName, validateServiceProvider(serviceProvider), monitor, false);
	}

	public ThreadedTableModelStub(String modelName, ServiceProvider serviceProvider,
			TaskMonitor monitor, boolean loadIncrementally) {
		super(modelName, validateServiceProvider(serviceProvider), monitor, loadIncrementally);
	}

	@Override
	/**
	 * Stubbed out to return null, as implementations of this stub do not need a data source.
	 * @return
	 */
	public final Object getDataSource() {
		return null;
	}
}
