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
package agent.dbgeng.impl.dbgeng.symbols;

import java.util.*;

import com.sun.jna.Native;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HRESULT;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugModule.DebugModuleName;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_MODULE_AND_ID;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_SYMBOL_ENTRY;
import agent.dbgeng.jna.dbgeng.symbols.IDebugSymbols3;

public class DebugSymbolsImpl3 extends DebugSymbolsImpl2 {
	private final IDebugSymbols3 jnaSymbols;

	public DebugSymbolsImpl3(IDebugSymbols3 jnaSymbols) {
		super(jnaSymbols);
		this.jnaSymbols = jnaSymbols;
	}

	@Override
	public int getCurrentScopeFrameIndex() {
		ULONGByReference pulIndex = new ULONGByReference();
		COMUtils.checkRC(jnaSymbols.GetCurrentScopeFrameIndex(pulIndex));
		return pulIndex.getValue().intValue();
	}

	@Override
	public void setCurrentScopeFrameIndex(int index) {
		ULONG ulIndex = new ULONG(index);
		HRESULT hr = jnaSymbols.SetCurrentScopeFrameIndex(ulIndex);
		COMUtils.checkRC(hr);
	}

	@Override
	public DebugModule getModuleByModuleName(String name, int startIndex) {
		ULONG ulStartIndex = new ULONG(startIndex);
		ULONGByReference pulIndex = new ULONGByReference();
		ULONGLONGByReference pullBase = new ULONGLONGByReference();
		COMUtils.checkRC(jnaSymbols.GetModuleByModuleNameWide(new WString(name), ulStartIndex,
			pulIndex, pullBase));
		return new DebugModuleImpl(this, pulIndex.getValue().intValue(),
			pullBase.getValue().longValue());
	}

	@Override
	public String getModuleName(DebugModuleName which, DebugModule module) {
		ULONG ulWhich = new ULONG(which.ordinal());
		ULONGLONG ullBase = new ULONGLONG(module.getBase());
		ULONGByReference pulNameSize = new ULONGByReference();
		COMUtils.checkRC(jnaSymbols.GetModuleNameStringWide(ulWhich, DbgEngUtil.DEBUG_ANY_ID,
			ullBase, null, new ULONG(0), pulNameSize));
		char[] aBuffer = new char[pulNameSize.getValue().intValue()];
		COMUtils.checkRC(jnaSymbols.GetModuleNameStringWide(ulWhich, DbgEngUtil.DEBUG_ANY_ID,
			ullBase, aBuffer, pulNameSize.getValue(), null));
		return Native.toString(aBuffer);
	}

	@Override
	public List<DebugSymbolId> getSymbolIdsByName(String pattern) {
		ULONGByReference pulEntries = new ULONGByReference();
		WString wsPattern = new WString(pattern);
		COMUtils.checkRC(jnaSymbols.GetSymbolEntriesByNameWide(wsPattern, new ULONG(0), null,
			new ULONG(0), pulEntries));
		if (pulEntries.getValue().intValue() == 0) {
			return Collections.emptyList();
		}
		DEBUG_MODULE_AND_ID[] aIds = (DEBUG_MODULE_AND_ID[]) new DEBUG_MODULE_AND_ID()
				.toArray(pulEntries.getValue().intValue());
		COMUtils.checkRC(jnaSymbols.GetSymbolEntriesByNameWide(wsPattern, new ULONG(0), aIds,
			pulEntries.getValue(), null));
		List<DebugSymbolId> result = new ArrayList<>(aIds.length);
		for (int i = 0; i < aIds.length; i++) {
			result.add(new DebugSymbolId(aIds[i].ModuleBase.longValue(), aIds[i].Id.longValue()));
		}
		return result;
	}

	@Override
	public DebugSymbolEntry getSymbolEntry(DebugSymbolId id) {
		DEBUG_MODULE_AND_ID sId = new DEBUG_MODULE_AND_ID();
		sId.ModuleBase = new ULONGLONG(id.moduleBase);
		sId.Id = new ULONGLONG(id.symbolIndex);
		DEBUG_SYMBOL_ENTRY.ByReference pInfo = new DEBUG_SYMBOL_ENTRY.ByReference();
		COMUtils.checkRC(jnaSymbols.GetSymbolEntryInformation(sId, pInfo));
		// Get the name while I'm here
		char[] aName = new char[pInfo.NameSize.intValue() + 1];
		COMUtils.checkRC(jnaSymbols.GetSymbolEntryStringWide(sId, new ULONG(0), aName,
			new ULONG(aName.length), null));
		return new DebugSymbolEntry(pInfo.ModuleBase.longValue(), pInfo.Offset.longValue(),
			pInfo.Id.longValue(), pInfo.Size.longValue(), pInfo.Flags.intValue(),
			pInfo.TypeId.intValue()/* TODO */, Native.toString(aName),
			pInfo.Tag.intValue()/* TODO */);
	}
}
