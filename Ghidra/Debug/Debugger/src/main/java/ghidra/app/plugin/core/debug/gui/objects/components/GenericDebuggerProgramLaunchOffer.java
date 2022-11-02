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
package ghidra.app.plugin.core.debug.gui.objects.components;

import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.debug.service.model.launch.AbstractDebuggerProgramLaunchOffer;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class GenericDebuggerProgramLaunchOffer extends AbstractDebuggerProgramLaunchOffer {

	private DebuggerObjectModel model;

	public GenericDebuggerProgramLaunchOffer(Program program, PluginTool tool,
			DebuggerObjectModel model) {
		super(program, tool, null);
		this.model = model;
	}

	@Override
	public String getConfigName() {
		return program.getName();
	}

	@Override
	public String getButtonTitle() {
		return "Launch";
	}

	@Override
	public String getMenuTitle() {
		return model.getBrief();
	}

	@Override
	public String getMenuParentTitle() {
		return model.getBrief();
	}

	protected CompletableFuture<DebuggerObjectModel> connect(boolean prompt) {
		throw new RuntimeException("Unable to connect using GenericDebuggerProgramLaunchOffer");
	}

}
