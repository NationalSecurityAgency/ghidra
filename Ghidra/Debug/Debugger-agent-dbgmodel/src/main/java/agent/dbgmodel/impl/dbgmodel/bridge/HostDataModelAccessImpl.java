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
package agent.dbgmodel.impl.dbgmodel.bridge;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgeng.dbgeng.DebugClient;
import agent.dbgeng.impl.dbgeng.client.DebugClientImpl1;
import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.datamodel.DataModelManager1;
import agent.dbgmodel.dbgmodel.debughost.DebugHost;
import agent.dbgmodel.impl.dbgmodel.datamodel.DataModelManagerInternal;
import agent.dbgmodel.impl.dbgmodel.debughost.DebugHostInternal;
import agent.dbgmodel.jna.dbgmodel.bridge.IHostDataModelAccess;
import agent.dbgmodel.jna.dbgmodel.datamodel.WrapIDataModelManager1;
import agent.dbgmodel.jna.dbgmodel.debughost.WrapIDebugHost;

public class HostDataModelAccessImpl implements HostDataModelAccessInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IHostDataModelAccess jnaData;

	private DataModelManager1 manager;
	private DebugHost host;
	private DebugClient debugClient;

	public HostDataModelAccessImpl(IHostDataModelAccess jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	public HostDataModelAccessImpl(DebugClient debugClient) {
		DebugClientImpl1 impl = (DebugClientImpl1) debugClient;
		this.jnaData = (IHostDataModelAccess) impl.getJNAClient();
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	public IHostDataModelAccess getJNAData() {
		return jnaData;
	}

	@Override
	public void getDataModel() {
		PointerByReference ppManager = new PointerByReference();
		PointerByReference ppHost = new PointerByReference();
		COMUtils.checkRC(jnaData.GetDataModel(ppManager, ppHost));

		WrapIDataModelManager1 wrap0 = new WrapIDataModelManager1(ppManager.getValue());
		try {
			manager = DataModelManagerInternal.tryPreferredInterfaces(wrap0::QueryInterface);
		}
		finally {
			wrap0.Release();
		}
		WrapIDebugHost wrap1 = new WrapIDebugHost(ppHost.getValue());
		try {
			host = DebugHostInternal.tryPreferredInterfaces(wrap1::QueryInterface);
		}
		finally {
			wrap1.Release();
		}
	}

	@Override
	public DataModelManager1 getManager() {
		return manager;
	}

	@Override
	public DebugHost getHost() {
		return host;
	}

	@Override
	public DebugClient getClient() {
		return debugClient;
	}

	@Override
	public void setClient(DebugClient debugClient) {
		this.debugClient = debugClient;
	}

}
