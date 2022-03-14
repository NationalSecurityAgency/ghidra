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
package ghidra.app.plugin.core.decompile.actions;

import java.util.Iterator;

import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;

/**
 * Task for creating a PCode data flow graph from a selected address
 */
public class SelectedPCodeDfgGraphTask extends PCodeDfgGraphTask {

	private Address address;

	public SelectedPCodeDfgGraphTask(PluginTool tool, GraphDisplayBroker graphService,
			HighFunction hfunction, Address address) {
		super(tool, graphService, hfunction);
		this.address = address;
	}

	protected Iterator<PcodeOpAST> getPcodeOpIterator() {
		Iterator<PcodeOpAST> opiter = hfunction.getPcodeOps(address);
		return opiter;
	}
}
