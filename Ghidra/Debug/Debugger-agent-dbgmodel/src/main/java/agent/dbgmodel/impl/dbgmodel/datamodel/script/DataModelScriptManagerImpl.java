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

import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.datamodel.script.*;
import agent.dbgmodel.jna.dbgmodel.datamodel.script.*;

public class DataModelScriptManagerImpl implements DataModelScriptManagerInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDataModelScriptManager jnaData;

	public DataModelScriptManagerImpl(IDataModelScriptManager jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public DataModelNameBinder getDefaultNameBinder() {
		PointerByReference ppNameBinder = new PointerByReference();
		COMUtils.checkRC(jnaData.GetDefaultNameBinder(ppNameBinder));

		WrapIDataModelNameBinder wrap = new WrapIDataModelNameBinder(ppNameBinder.getValue());
		try {
			return DataModelNameBinderInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public void registerScriptProvider(DataModelScriptProvider provider) {
		Pointer pProvider = provider.getPointer();
		COMUtils.checkRC(jnaData.RegisterScriptProvider(pProvider));
	}

	@Override
	public void unregisterScriptProvider(DataModelScriptProvider provider) {
		Pointer pProvider = provider.getPointer();
		COMUtils.checkRC(jnaData.UnregisterScriptProvider(pProvider));
	}

	@Override
	public DataModelScriptProvider findProviderForScriptType(String scriptType) {
		WString wScriptType = new WString(scriptType);
		PointerByReference ppProvider = new PointerByReference();
		COMUtils.checkRC(jnaData.FindProviderForScriptType(wScriptType, ppProvider));

		WrapIDataModelScriptProvider wrap = new WrapIDataModelScriptProvider(ppProvider.getValue());
		try {
			return DataModelScriptProviderInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DataModelScriptProvider findProviderForScriptExtension(String scriptExtension) {
		WString wScriptExtension = new WString(scriptExtension);
		PointerByReference ppProvider = new PointerByReference();
		COMUtils.checkRC(jnaData.FindProviderForScriptType(wScriptExtension, ppProvider));

		WrapIDataModelScriptProvider wrap = new WrapIDataModelScriptProvider(ppProvider.getValue());
		try {
			return DataModelScriptProviderInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DataModelScriptProviderEnumerator enumeratorScriptProviders() {
		PointerByReference ppEnumerator = new PointerByReference();
		COMUtils.checkRC(jnaData.EnumerateScriptProviders(ppEnumerator));

		WrapIDataModelScriptProviderEnumerator wrap =
			new WrapIDataModelScriptProviderEnumerator(ppEnumerator.getValue());
		try {
			return DataModelScriptProviderEnumeratorInternal.tryPreferredInterfaces(
				wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}
}
