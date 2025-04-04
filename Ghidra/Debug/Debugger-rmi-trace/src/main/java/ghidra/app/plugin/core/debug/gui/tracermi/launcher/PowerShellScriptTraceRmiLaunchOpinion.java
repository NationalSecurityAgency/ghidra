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
package ghidra.app.plugin.core.debug.gui.tracermi.launcher;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import generic.jar.ResourceFile;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.framework.OperatingSystem;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class PowerShellScriptTraceRmiLaunchOpinion extends AbstractTraceRmiLaunchOpinion {

	@Override
	public Collection<TraceRmiLaunchOffer> getOffers(TraceRmiLauncherServicePlugin plugin,
			Program program) {
		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			return getScriptPaths(plugin.getTool())
					.flatMap(rf -> Stream.of(rf.listFiles(crf -> crf.getName().endsWith(".ps1"))))
					.flatMap(sf -> createOffer(plugin, program, sf))
					.collect(Collectors.toList());
		}
		return List.of();
	}

	protected Stream<TraceRmiLaunchOffer> createOffer(TraceRmiLauncherServicePlugin plugin,
			Program program, ResourceFile scriptFile) {
		try {
			return Stream.of(PowerShellScriptTraceRmiLaunchOffer.create(plugin, program,
				scriptFile.getFile(false)));
		}
		catch (Exception e) {
			Msg.error(this, "Could not offer " + scriptFile + ": " + e.getMessage(), e);
			return Stream.of();
		}
	}
}
