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

import java.math.BigInteger;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

import agent.frida.frida.FridaEng;

public class FridaTarget extends FridaPointer {

	private String id;
	private String name;
	private FridaSession session;

	public FridaTarget(Pointer device, String id, String name) {
		super(device);
		this.id = id;
		this.name = name;
	}

	public FridaSession attach(BigInteger processId, FridaError error) {
		return FridaEng.attach(this, new NativeLong(processId.longValue()), error);
	}

	public FridaSession launchSimple(String[] argArr, String[] envArr, String workingDir) {
		return FridaEng.spawn(this, argArr[0], new FridaError());
	}

	public FridaSession launch(String fileName, String[] argArr, String[] envArr, String pathSTDIN,
			String pathSTDOUT, String pathSTDERR, String workingDir, long createFlags,
			boolean stopAtEntry,
			FridaError error) {
		return FridaEng.spawn(this, fileName, error);
	}

	public void resumeProcess(NativeLong processId, FridaError error) {
		FridaEng.resume(this, processId, error);
	}

	public void killProcess(NativeLong processId, FridaError error) {
		FridaEng.kill(this, processId, error);
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
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

	public FridaProcess getProcess() {
		return session == null ? null : session.getProcess();
	}

}
