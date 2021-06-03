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
package agent.dbgeng.impl.dbgeng.client;

import agent.dbgeng.jna.dbgeng.client.IDebugClient7;

public class DebugClientImpl7 extends DebugClientImpl6 {
	@SuppressWarnings("unused")
	private final IDebugClient7 jnaClient;

	public DebugClientImpl7(IDebugClient7 jnaClient) {
		super(jnaClient);
		this.jnaClient = jnaClient;
	}
}
