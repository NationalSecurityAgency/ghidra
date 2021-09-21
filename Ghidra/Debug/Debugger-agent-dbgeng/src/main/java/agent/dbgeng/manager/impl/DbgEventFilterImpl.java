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
package agent.dbgeng.manager.impl;

import agent.dbgeng.manager.DbgEventFilter;

public class DbgEventFilterImpl implements DbgEventFilter {
	private final String text;
	private final String cmd;

	public DbgEventFilterImpl(String text, String cmd) {
		this.text = text;
		this.cmd = cmd;
	}

	@Override
	public String getName() {
		return text;
	}

	@Override
	public String getCmd() {
		return cmd;
	}

}
