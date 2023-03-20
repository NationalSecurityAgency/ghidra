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

import java.util.List;
import java.util.Map;

import com.sun.jna.Pointer;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugModule.DebugModuleName;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.InterfaceSupplier;
import agent.dbgeng.impl.dbgeng.DbgEngUtil.Preferred;
import agent.dbgeng.jna.dbgeng.symbols.*;
import ghidra.util.datastruct.WeakValueHashMap;

public interface DebugSymbolsInternal extends DebugSymbols {
	final Map<Pointer, DebugSymbolsInternal> CACHE = new WeakValueHashMap<>();

	static DebugSymbolsInternal instanceFor(WrapIDebugSymbols symbols) {
		return DbgEngUtil.lazyWeakCache(CACHE, symbols, DebugSymbolsImpl1::new);
	}

	static DebugSymbolsInternal instanceFor(WrapIDebugSymbols2 symbols) {
		return DbgEngUtil.lazyWeakCache(CACHE, symbols, DebugSymbolsImpl2::new);
	}

	static DebugSymbolsInternal instanceFor(WrapIDebugSymbols3 symbols) {
		return DbgEngUtil.lazyWeakCache(CACHE, symbols, DebugSymbolsImpl3::new);
	}

	static DebugSymbolsInternal instanceFor(WrapIDebugSymbols4 symbols) {
		return DbgEngUtil.lazyWeakCache(CACHE, symbols, DebugSymbolsImpl4::new);
	}

	static DebugSymbolsInternal instanceFor(WrapIDebugSymbols5 symbols) {
		return DbgEngUtil.lazyWeakCache(CACHE, symbols, DebugSymbolsImpl5::new);
	}

	List<Preferred<WrapIDebugSymbols>> PREFFERED_SYMBOLS_IIDS = List.of(
		new Preferred<>(IDebugSymbols5.IID_IDEBUG_SYMBOLS5, WrapIDebugSymbols5.class),
		new Preferred<>(IDebugSymbols4.IID_IDEBUG_SYMBOLS4, WrapIDebugSymbols4.class),
		new Preferred<>(IDebugSymbols3.IID_IDEBUG_SYMBOLS3, WrapIDebugSymbols3.class),
		new Preferred<>(IDebugSymbols2.IID_IDEBUG_SYMBOLS2, WrapIDebugSymbols2.class),
		new Preferred<>(IDebugSymbols.IID_IDEBUG_SYMBOLS, WrapIDebugSymbols.class));

	static DebugSymbolsInternal tryPreferredInterfaces(InterfaceSupplier supplier) {
		return DbgEngUtil.tryPreferredInterfaces(DebugSymbolsInternal.class, PREFFERED_SYMBOLS_IIDS,
			supplier);
	}

	String getModuleName(DebugModuleName which, DebugModule module);

	@Override
	DebugModuleInfo getModuleParameters(int count, int startIndex);

}
