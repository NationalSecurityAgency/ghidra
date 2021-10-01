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

import agent.dbgeng.manager.DbgExceptionFilter;

public class DbgExceptionFilterImpl extends DbgEventFilterImpl implements DbgExceptionFilter {

	private final String cmd2;
	private long exceptionCode;

	public DbgExceptionFilterImpl(int index, String text, String cmd, String cmd2,
			int executionOption,
			int continueOption, long exceptionCode) {
		super(index, text, cmd, null, executionOption, continueOption);
		this.cmd2 = cmd2;
		this.exceptionCode = exceptionCode;
	}

	public String getSecondCmd() {
		return cmd2;
	}

	public String getExceptionCode() {
		return Long.toHexString(exceptionCode);
	}

}
