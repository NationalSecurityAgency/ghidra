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
package agent.frida.frida;

import java.util.HashMap;
import java.util.Map;

import agent.frida.manager.*;

/**
 * Information about a module (program or library image).
 * 
 * The fields correspond to the parameters taken by {@code LoadModule} of
 * {@code IDebugEventCallbacks}. They also appear as a subset of parameters taken by
 * {@code CreateProcess} of {@code IDebugEventCallbacks}.
 */
public class FridaModuleInfo {

	private FridaProcess process;
	private long numModules;
	private Map<Integer, FridaModule> modules = new HashMap<>();

	public FridaModuleInfo(FridaProcess process, FridaModule module) {
		this.process = process;
		numModules = 1;
		modules.put(0, module);
	}

	public FridaModuleInfo(FridaKernelModule module) {
		this.process = null;
		numModules = 1;
		modules.put(0, module);
	}

	public Long getNumberOfModules() {
		return numModules;
	}

	public FridaModule getModule(int index) {
		return modules.get(index);
	}

	public String toString(int index) {
		FridaModule module = modules.get(index);
		return module.toString();
	}

	public String getModuleName(int index) {
		FridaModule module = modules.get(index);
		return FridaClient.getId(module);
	}

	public void setModuleName(int index, String moduleName) {
		FridaModule module = modules.get(index);
		module.setName(moduleName);
	}

	public String getImageName(int index) {
		FridaModule module = modules.get(index);
		return module.getPath();
	}

	public void setImageName(int index, String dirName, String imageName) {
		FridaModule module = modules.get(index);
		module.setPath(imageName);
	}

	public FridaProcess getProcess() {
		return process;
	}
}
