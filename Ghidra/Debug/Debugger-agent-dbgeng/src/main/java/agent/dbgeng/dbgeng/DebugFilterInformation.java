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

public class DebugFilterInformation {

	private int nEvents;
	private int nSpecificExceptions;
	private int nArbitraryExceptions;

	public DebugFilterInformation(int nEvents, int nSpecificExceptions, int nArbitraryExceptions) {
		this.nEvents = nEvents;
		this.nSpecificExceptions = nSpecificExceptions;
		this.nArbitraryExceptions = nArbitraryExceptions;
	}

	public int getNumberEvents() {
		return nEvents;
	}

	public int getNumberSpecificExceptions() {
		return nSpecificExceptions;
	}

	public int getNumberArbitraryExceptions() {
		return nArbitraryExceptions;
	}

}
