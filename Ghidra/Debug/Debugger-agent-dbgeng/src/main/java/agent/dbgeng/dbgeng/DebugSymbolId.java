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

/**
 * Symbol identifier, consisting of module ID and symbol index.
 */
public class DebugSymbolId {
	public final long moduleBase;
	public final long symbolIndex;

	public DebugSymbolId(long moduleBase, long symbolIndex) {
		this.moduleBase = moduleBase;
		this.symbolIndex = symbolIndex;
	}

	@Override
	public String toString() {
		return String.format("<DebugSymbolId %016x:%016x>", moduleBase, symbolIndex);
	}
}
