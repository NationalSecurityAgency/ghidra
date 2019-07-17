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
// An example of how to create Version Tracking session, run some correlators to find matching
// data and and then save the session.
//@category Examples.Version Tracking

import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.actions.AutoVersionTrackingCommand;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class AutoVersionTrackingScript extends GhidraScript {
	@Override
	public void run() throws Exception {

		DomainFolder folder =
			askProjectFolder("Please choose a folder for your Version Tracking session.");
		String name = askString("Please enter a Version Tracking session name", "Session Name");

		Program sourceProgram;
		Program destinationProgram;

		boolean isCurrentProgramSourceProg = askYesNo("Current Program Source Program?",
			"Is the current program your source program?");

		if (isCurrentProgramSourceProg) {
			sourceProgram = currentProgram;
			destinationProgram = askProgram("Please select the destination (new) program");
		}
		else {
			destinationProgram = currentProgram;
			sourceProgram = askProgram("Please select the source (existing annotated) program");
		}

		// Need to end the script transaction or it interferes with vt things that need locks
		end(true);

		VTSession session =
			VTSessionDB.createVTSession(name, sourceProgram, destinationProgram, this);

		folder.createFile(name, session, monitor);

		PluginTool tool = state.getTool();
		VTPlugin vtPlugin = getPlugin(tool, VTPlugin.class);
		if (vtPlugin == null) {
			tool.addPlugin(VTPlugin.class.getName());
			vtPlugin = getPlugin(tool, VTPlugin.class);
		}

		VTController controller = new VTControllerImpl(vtPlugin);

		//String description = "AutoVTScript";

		AutoVersionTrackingCommand autoVTcmd =
			new AutoVersionTrackingCommand(controller, session, 1.0, 10.0);

		controller.getTool().executeBackgroundCommand(autoVTcmd, session);
		//destinationProgram.save(description, monitor);

		//session.save(description, monitor);
		//session.release(this);

	}

	public static <T extends Plugin> T getPlugin(PluginTool tool, Class<T> c) {
		List<Plugin> list = tool.getManagedPlugins();
		Iterator<Plugin> it = list.iterator();
		while (it.hasNext()) {
			Plugin p = it.next();
			if (p.getClass() == c) {
				return c.cast(p);
			}
		}
		return null;
	}

}
