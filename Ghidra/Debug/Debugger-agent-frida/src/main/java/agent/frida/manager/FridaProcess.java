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

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

public class FridaProcess extends FridaPointer {

	private NativeLong pid;
	private String name;
	private FridaSession session;
	private String identifier;

	public FridaProcess(Pointer process, NativeLong pid) {
		super(process);
		this.pid = pid;
	}

	// Kernel-case
	public FridaProcess() {
		super(null);
		this.pid = new NativeLong(-1L);
	}

	public Long getPID() {
		return pid.longValue();
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public FridaSession getSession() {
		return session;
	}
	
	public void setSession(FridaSession session) {
		this.session = session;
	}

	public String getIdentifier() {
		return identifier;
	}
	
	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}

	public FridaTarget getTarget() {
		return session.getTarget();
	}

	public FridaError resume() {
		FridaTarget target = getTarget();
		FridaError error = new FridaError();
		target.resumeProcess(pid, error);
		return error;
	}

	public FridaError destroy() {
		FridaTarget target = getTarget();
		FridaError error = new FridaError();
		target.killProcess(pid, error);
		return error;
	}

	public FridaError kill() {
		FridaTarget target = getTarget();
		FridaError error = new FridaError();
		target.killProcess(pid, error);
		return error;
	}

	public String getDescription() {
		return getName();
	}

}
