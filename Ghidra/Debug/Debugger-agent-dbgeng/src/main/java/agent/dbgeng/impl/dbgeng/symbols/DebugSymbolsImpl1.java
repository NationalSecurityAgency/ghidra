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

import java.util.Iterator;
import java.util.List;

import com.sun.jna.Native;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.COM.COMException;
import com.sun.jna.platform.win32.COM.COMUtils;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DbgEng.OpaqueCleanable;
import agent.dbgeng.dbgeng.DebugModule.DebugModuleName;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.jna.dbgeng.DbgEngNative.DEBUG_MODULE_PARAMETERS;
import agent.dbgeng.jna.dbgeng.symbols.IDebugSymbols;

public class DebugSymbolsImpl1 implements DebugSymbolsInternal {
	@SuppressWarnings("unused")
	private final OpaqueCleanable cleanable;
	private final IDebugSymbols jnaSymbols;

	public DebugSymbolsImpl1(IDebugSymbols jnaSymbols) {
		this.cleanable = DbgEng.releaseWhenPhantom(this, jnaSymbols);
		this.jnaSymbols = jnaSymbols;
	}

	@Override
	public int getNumberLoadedModules() {
		ULONGByReference pulLoaded = new ULONGByReference();
		ULONGByReference pulUnloaded = new ULONGByReference();
		COMUtils.checkRC(jnaSymbols.GetNumberModules(pulLoaded, pulUnloaded));
		return pulLoaded.getValue().intValue();
	}

	@Override
	public int getNumberUnloadedModules() {
		ULONGByReference pulLoaded = new ULONGByReference();
		ULONGByReference pulUnloaded = new ULONGByReference();
		COMUtils.checkRC(jnaSymbols.GetNumberModules(pulLoaded, pulUnloaded));
		return pulUnloaded.getValue().intValue();
	}

	@Override
	public DebugModule getModuleByIndex(int index) {
		ULONG ulIndex = new ULONG(index);
		ULONGLONGByReference pullBase = new ULONGLONGByReference();
		COMUtils.checkRC(jnaSymbols.GetModuleByIndex(ulIndex, pullBase));
		return new DebugModuleImpl(this, index, pullBase.getValue().longValue());
	}

	@Override
	public DebugModule getModuleByModuleName(String name, int startIndex) {
		ULONG ulStartIndex = new ULONG(startIndex);
		ULONGByReference pulIndex = new ULONGByReference();
		ULONGLONGByReference pullBase = new ULONGLONGByReference();
		COMUtils.checkRC(jnaSymbols.GetModuleByModuleName(name, ulStartIndex, pulIndex, pullBase));
		return new DebugModuleImpl(this, pulIndex.getValue().intValue(),
			pullBase.getValue().longValue());
	}

	@Override
	public DebugModule getModuleByOffset(long offset, int startIndex) {
		ULONGLONG ullOffset = new ULONGLONG(offset);
		ULONG ulStartIndex = new ULONG(startIndex);
		ULONGByReference pulIndex = new ULONGByReference();
		ULONGLONGByReference pullBase = new ULONGLONGByReference();
		COMUtils.checkRC(jnaSymbols.GetModuleByOffset(ullOffset, ulStartIndex, pulIndex, pullBase));
		return new DebugModuleImpl(this, pulIndex.getValue().intValue(),
			pullBase.getValue().longValue());
	}

	protected void callNamesForWhich(DebugModuleName which, ULONG Index, ULONGLONG Base,
			byte[] Buffer, ULONG BufferSize, ULONGByReference NameSize) {
		switch (which) {
			case IMAGE:
				COMUtils.checkRC(jnaSymbols.GetModuleNames(Index, Base, Buffer, BufferSize,
					NameSize, null, new ULONG(0), null, null, new ULONG(0), null));
			case MODULE:
				COMUtils.checkRC(jnaSymbols.GetModuleNames(Index, Base, null, new ULONG(0), null,
					Buffer, BufferSize, NameSize, null, new ULONG(0), null));
			case LOADED_IMAGE:
				COMUtils.checkRC(jnaSymbols.GetModuleNames(Index, Base, null, new ULONG(0), null,
					null, new ULONG(0), null, Buffer, BufferSize, NameSize));
			default:
				throw new UnsupportedOperationException("Interface does not support " + which);
		}
	}

	@Override
	public String getModuleName(DebugModuleName which, DebugModule module) {
		ULONGLONG ullBase = new ULONGLONG(module.getBase());
		ULONGByReference pulNameSize = new ULONGByReference();
		callNamesForWhich(which, DbgEngUtil.DEBUG_ANY_ID, ullBase, null, new ULONG(0), pulNameSize);
		byte[] aBuffer = new byte[pulNameSize.getValue().intValue()];
		callNamesForWhich(which, DbgEngUtil.DEBUG_ANY_ID, ullBase, aBuffer, pulNameSize.getValue(),
			null);
		return Native.toString(aBuffer);
	}

	@Override
	public DebugModuleInfo getModuleParameters(int count, int startIndex) {
		ULONG ulCount = new ULONG(count);
		ULONG ulStartIndex = new ULONG(startIndex);
		DEBUG_MODULE_PARAMETERS.ByReference pInfo = new DEBUG_MODULE_PARAMETERS.ByReference();
		COMUtils.checkRC(jnaSymbols.GetModuleParameters(ulCount, null, ulStartIndex, pInfo));
		return new DebugModuleInfo(0L, pInfo.Base.longValue(), pInfo.Size.intValue(), "", "",
			pInfo.Checksum.intValue(), pInfo.TimeDateStamp.intValue());
	}

	@Override
	public Iterable<DebugSymbolName> iterateSymbolMatches(String pattern) {
		ULONGLONGByReference pullHandle = new ULONGLONGByReference();
		return new Iterable<DebugSymbolName>() {
			@Override
			public Iterator<DebugSymbolName> iterator() {
				COMUtils.checkRC(jnaSymbols.StartSymbolMatch(pattern, pullHandle));
				return new Iterator<DebugSymbolName>() {
					ULONGByReference pulMatchSize = new ULONGByReference();
					ULONGLONGByReference pullOffset = new ULONGLONGByReference();

					@Override
					public boolean hasNext() {
						try {
							COMUtils.checkRC(jnaSymbols.GetNextSymbolMatch(pullHandle.getValue(),
								null, new ULONG(0), pulMatchSize, null));
						}
						catch (COMException e) {
							if (!COMUtilsExtra.isE_NOINTERFACE(e)) {
								throw e;
							}
							return false;
						}
						return true;
					}

					@Override
					public DebugSymbolName next() {
						try {
							if (pulMatchSize.getValue().intValue() == 0) {
								COMUtils.checkRC(jnaSymbols.GetNextSymbolMatch(
									pullHandle.getValue(), null, new ULONG(0), pulMatchSize, null));
							}
							byte[] aBuffer = new byte[pulMatchSize.getValue().intValue()];
							COMUtils.checkRC(jnaSymbols.GetNextSymbolMatch(pullHandle.getValue(),
								aBuffer, pulMatchSize.getValue(), null, pullOffset));
							return new DebugSymbolName(Native.toString(aBuffer),
								pullOffset.getValue().longValue());
						}
						catch (COMException e) {
							if (!COMUtilsExtra.isE_NOINTERFACE(e)) {
								throw e;
							}
							return null;
						}
						finally {
							pulMatchSize.getValue().setValue(0);
						}
					}

					@Override
					protected void finalize() throws Throwable {
						COMUtils.checkRC(jnaSymbols.EndSymbolMatch(pullHandle.getValue()));
					}
				};
			}
		};
	}

	@Override
	public List<DebugSymbolId> getSymbolIdsByName(String pattern) {
		throw new UnsupportedOperationException("Not supported by this interface");
	}

	@Override
	public DebugSymbolEntry getSymbolEntry(DebugSymbolId id) {
		throw new UnsupportedOperationException("Not supported by this interface");
	}

	@Override
	public String getSymbolPath() {
		ULONGByReference pulPathLength = new ULONGByReference();
		COMUtils.checkRC(jnaSymbols.GetSymbolPath(null, new ULONG(0), pulPathLength));
		byte[] aBuffer = new byte[pulPathLength.getValue().intValue()];
		COMUtils.checkRC(jnaSymbols.GetSymbolPath(aBuffer, pulPathLength.getValue(), null));
		return Native.toString(aBuffer);
	}

	@Override
	public void setSymbolPath(String path) {
		//WString wPath = new WString(path);
		COMUtils.checkRC(jnaSymbols.SetSymbolPath(path));
	}

	@Override
	public int getSymbolOptions() {
		ULONGByReference pulOptions = new ULONGByReference();
		COMUtils.checkRC(jnaSymbols.GetSymbolPath(null, new ULONG(0), pulOptions));
		return pulOptions.getValue().intValue();
	}

	@Override
	public void setSymbolOptions(int options) {
		ULONG ulOptions = new ULONG(options);
		COMUtils.checkRC(jnaSymbols.SetSymbolOptions(ulOptions));
	}

	@Override
	public int getCurrentScopeFrameIndex() {
		throw new UnsupportedOperationException("Not supported by this interface");
	}

	@Override
	public void setCurrentScopeFrameIndex(int index) {
		throw new UnsupportedOperationException("Not supported by this interface");
	}
}
