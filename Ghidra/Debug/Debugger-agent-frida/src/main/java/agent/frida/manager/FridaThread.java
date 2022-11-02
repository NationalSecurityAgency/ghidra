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
package agent.frida.manager;

public class FridaThread {
	
	private FridaProcess process;
	private Long tid;
	private FridaState state;
	private FridaContext context;

	public FridaThread(FridaProcess process) {
		this.process = process;
	}

	public Long getTid() {
		return tid;
	}

	public void setTid(Long tid) {
		this.tid = tid;
	}

	public FridaState getState() {
		return state;
	}

	public void setState(FridaState state) {
		this.state = state;
	}

	public FridaContext getContext() {
		return context;
	}
	
	public void setContext(FridaContext context) {
		this.context = context;
	}

	public FridaProcess getProcess() {
		return process;
	}

	public String getDescription() {
		return Long.toString(getTid());
	}

}
