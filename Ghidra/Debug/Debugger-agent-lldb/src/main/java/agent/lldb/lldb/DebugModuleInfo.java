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
package agent.lldb.lldb;

import java.util.HashMap;
import java.util.Map;

import SWIG.*;

/**
 * Information about a module (program or library image).
 * 
 * The fields correspond to the parameters taken by {@code LoadModule} of
 * {@code IDebugEventCallbacks}. They also appear as a subset of parameters taken by
 * {@code CreateProcess} of {@code IDebugEventCallbacks}.
 */
public class DebugModuleInfo {

	public SBEvent event;
	private SBProcess process;
	private long numModules;
	private Map<Integer, SBModule> modules = new HashMap<>();

	public DebugModuleInfo(SBEvent event) {
		this.event = event;
		numModules = SBTarget.GetNumModulesFromEvent(event);
		for (int i = 0; i < numModules; i++) {
			SBModule module = SBTarget.GetModuleAtIndexFromEvent(i, event);
			modules.put(i, module);
		}
	}

	public DebugModuleInfo(SBProcess process, SBModule module) {
		this.process = process;
		this.event = null;
		numModules = 1;
		modules.put(0, module);
	}

	public Long getNumberOfModules() {
		return numModules;
	}

	public SBModule getModule(int index) {
		return modules.get(index);
	}

	public String toString(int index) {
		SBModule module = modules.get(index);
		return module.toString();
	}

	public String getModuleName(int index) {
		SBModule module = modules.get(index);
		return DebugClient.getId(module);
	}

	public void setModuleName(int index, String moduleName) {
		SBModule module = modules.get(index);
		SBFileSpec filespec = module.GetFileSpec();
		filespec.SetFilename(moduleName);
	}

	public String getImageName(int index) {
		SBModule module = modules.get(index);
		SBFileSpec filespec = module.GetFileSpec();
		return filespec.GetDirectory() + ":" + filespec.GetFilename();
	}

	public void setImageName(int index, String dirName, String imageName) {
		SBModule module = modules.get(index);
		SBFileSpec filespec = module.GetFileSpec();
		filespec.SetDirectory(dirName);
		filespec.SetFilename(imageName);
	}

	public SBProcess getProcess() {
		return event != null ? SBProcess.GetProcessFromEvent(event) : process;
	}
}
