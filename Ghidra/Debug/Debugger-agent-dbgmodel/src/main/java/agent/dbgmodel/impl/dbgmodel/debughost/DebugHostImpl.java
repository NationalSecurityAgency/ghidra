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

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.COM.COMUtils;
import com.sun.jna.ptr.PointerByReference;

import agent.dbgmodel.dbgmodel.DbgModel;
import agent.dbgmodel.dbgmodel.DbgModel.OpaqueCleanable;
import agent.dbgmodel.dbgmodel.UnknownEx;
import agent.dbgmodel.dbgmodel.debughost.*;
import agent.dbgmodel.dbgmodel.main.KeyStore;
import agent.dbgmodel.impl.dbgmodel.UnknownExInternal;
import agent.dbgmodel.impl.dbgmodel.main.KeyStoreInternal;
import agent.dbgmodel.jna.dbgmodel.WrapIUnknownEx;
import agent.dbgmodel.jna.dbgmodel.debughost.IDebugHost;
import agent.dbgmodel.jna.dbgmodel.debughost.WrapIDebugHostContext;
import agent.dbgmodel.jna.dbgmodel.main.WrapIKeyStore;

public class DebugHostImpl implements DebugHostInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugHost jnaData;

	public DebugHostImpl(IDebugHost jnaData) {
		this.cleanable = DbgModel.releaseWhenPhantom(this, jnaData);
		this.jnaData = jnaData;
	}

	@Override
	public Pointer getPointer() {
		return jnaData.getPointer();
	}

	@Override
	public UnknownEx getHostDefinedInterface() {
		PointerByReference ppHostUnk = new PointerByReference();
		COMUtils.checkRC(jnaData.GetHostDefinedInterface(ppHostUnk));

		WrapIUnknownEx wrap = new WrapIUnknownEx(ppHostUnk.getValue());
		try {
			return UnknownExInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostContext getCurrentContext() {
		PointerByReference ppContext = new PointerByReference();
		COMUtils.checkRC(jnaData.GetCurrentContext(ppContext));

		WrapIDebugHostContext wrap = new WrapIDebugHostContext(ppContext.getValue());
		try {
			return DebugHostContextInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public KeyStore getDefaultMetadata() {
		PointerByReference ppDefaultMetadataStore = new PointerByReference();
		COMUtils.checkRC(jnaData.GetDefaultMetadata(ppDefaultMetadataStore));

		WrapIKeyStore wrap = new WrapIKeyStore(ppDefaultMetadataStore.getValue());
		try {
			return KeyStoreInternal.tryPreferredInterfaces(wrap::QueryInterface);
		}
		finally {
			wrap.Release();
		}
	}

	@Override
	public DebugHostMemory1 asMemory() {
		return DebugHostMemoryInternal.tryPreferredInterfaces(jnaData::QueryInterface);
	}

	@Override
	public DebugHostSymbols asSymbols() {
		return DebugHostSymbolsInternal.tryPreferredInterfaces(jnaData::QueryInterface);
	}

	@Override
	public DebugHostScriptHost asScriptHost() {
		return DebugHostScriptHostInternal.tryPreferredInterfaces(jnaData::QueryInterface);
	}

	@Override
	public DebugHostEvaluator2 asEvaluator() {
		return (DebugHostEvaluator2) DebugHostEvaluatorInternal.tryPreferredInterfaces(
			jnaData::QueryInterface);
	}
}
