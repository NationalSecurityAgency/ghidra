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
 * Symbol name, consisting of textual name and offset.
 */
public class DebugSymbolName {
	public final String name;
	public final long offset;

	public DebugSymbolName(String name, long offset) {
		this.name = name;
		this.offset = offset;
	}

	@Override
	public String toString() {
		return String.format("<%016x: %s>", offset, name);
	}
}
