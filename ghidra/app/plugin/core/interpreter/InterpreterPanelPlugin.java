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
package ghidra.app.plugin.core.interpreter;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Interpreter panel service",
	description = "Provides a generic interpreter connection and mates it to a panel"
			+ " which takes input from the user and displays output from the interpreter.",
	servicesProvided = { InterpreterPanelService.class }
)
//@formatter:on
public class InterpreterPanelPlugin extends Plugin implements InterpreterPanelService {

	public InterpreterPanelPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public InterpreterConsole createInterpreterPanel(InterpreterConnection interpreter,
			boolean visible) {
		return new InterpreterComponentProvider(this, interpreter, visible);
	}

}
