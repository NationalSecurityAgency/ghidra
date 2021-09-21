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

public class DbgExceptionFilterImpl implements DbgExceptionFilter {
	private final String text;
	private final String cmd;
	private final String cmd2;
	private int executionOption;
	private int continueOption;
	private long exceptionCode;

	public DbgExceptionFilterImpl(String text, String cmd, String cmd2, int executionOption,
			int continueOption, long exceptionCode) {
		this.text = text;
		this.cmd = cmd;
		this.cmd2 = cmd2;
		this.setExecutionOption(executionOption);
		this.setContinueOption(continueOption);
		this.exceptionCode = exceptionCode;
	}

	@Override
	public String getName() {
		return text;
	}

	@Override
	public String getCmd() {
		return cmd;
	}

	public String getSecondCmd() {
		return cmd2;
	}

	public int getExecutionOption() {
		return executionOption;
	}

	public void setExecutionOption(int executionOption) {
		this.executionOption = executionOption;
	}

	public int getContinueOption() {
		return continueOption;
	}

	public void setContinueOption(int continueOption) {
		this.continueOption = continueOption;
	}

	public long getExceptionCode() {
		return exceptionCode;
	}

}
