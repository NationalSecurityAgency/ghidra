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
package agent.dbgeng.manager.reason;

import java.util.Map;

import agent.dbgeng.manager.DbgReason;

/**
 * The inferior stopped because it has exited (with status 0)
 */
public class DbgExitNormallyReason implements DbgReason {
	public DbgExitNormallyReason(Map<String, Object> info) {
		// Nothing additional to parse
	}

	@Override
	public String desc() {
		return "Exited normally";
	}
}
