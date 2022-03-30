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
 * 
 * The fields correspond to the parameters taken by {@code LoadModule} of
 * {@code IDebugEventCallbacks}. They also appear as a subset of parameters taken by
 * {@code CreateProcess} of {@code IDebugEventCallbacks}.
 */
public class FridaRegionInfo {

	private FridaProcess process;
	private long numRegions;
	private Map<Integer, FridaMemoryRegionInfo> regions = new HashMap<>();

	public FridaRegionInfo(FridaProcess process, FridaMemoryRegionInfo region) {
		this.process = process;
		numRegions = 1;
		regions.put(0, region);
	}

	public FridaRegionInfo(FridaKernelMemoryRegionInfo region) {
		this.process = null;
		numRegions = 1;
		regions.put(0, region);
	}

	public Long getNumberOfRegions() {
		return numRegions;
	}

	public FridaMemoryRegionInfo getRegion(int index) {
		return regions.get(index);
	}

	public String toString(int index) {
		FridaMemoryRegionInfo region = regions.get(index);
		return region.toString();
	}

	public String getRegionName(int index) {
		FridaMemoryRegionInfo region = regions.get(index);
		return FridaClient.getId(region);
	}

	public void setRegionName(int index, String regionName) {
		FridaMemoryRegionInfo region = regions.get(index);
		FridaFileSpec filespec = region.getFileSpec();
		if (filespec != null) {
			filespec.setPath(regionName);
		}	
	}

	public FridaProcess getProcess() {
		return process;
	}
}
