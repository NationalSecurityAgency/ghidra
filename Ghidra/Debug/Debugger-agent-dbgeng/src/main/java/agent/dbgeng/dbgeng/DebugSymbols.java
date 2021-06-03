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
package agent.dbgeng.dbgeng;

import java.util.Iterator;
import java.util.List;

/**
 * A wrapper for {@code IDebugSymbols} and its newer variants.
 */
public interface DebugSymbols {
	int getNumberLoadedModules();

	int getNumberUnloadedModules();

	DebugModule getModuleByIndex(int index);

	DebugModule getModuleByModuleName(String name, int startIndex);

	DebugModule getModuleByOffset(long offset, int startIndex);

	DebugModuleInfo getModuleParameters(int count, int startIndex);

	/**
	 * A shortcut for iterating over all loaded modules, lazily.
	 * 
	 * @param startIndex the module index to start at
	 * @return an iterator over modules starting at the given index
	 */
	default Iterable<DebugModule> iterateModules(int startIndex) {
		int count = getNumberLoadedModules(); // TODO: What about unloaded?
		return new Iterable<DebugModule>() {
			@Override
			public Iterator<DebugModule> iterator() {
				return new Iterator<DebugModule>() {
					int cur = startIndex;

					@Override
					public boolean hasNext() {
						return cur < count;
					}

					@Override
					public DebugModule next() {
						DebugModule ret = getModuleByIndex(cur);
						cur++;
						return ret;
					}
				};
			}
		};
	}

	Iterable<DebugSymbolName> iterateSymbolMatches(String pattern);

	List<DebugSymbolId> getSymbolIdsByName(String pattern);

	DebugSymbolEntry getSymbolEntry(DebugSymbolId id);

	String getSymbolPath();

	void setSymbolPath(String path);

	int getSymbolOptions();

	void setSymbolOptions(int options);

	public int getCurrentScopeFrameIndex();

	public void setCurrentScopeFrameIndex(int index);

}
