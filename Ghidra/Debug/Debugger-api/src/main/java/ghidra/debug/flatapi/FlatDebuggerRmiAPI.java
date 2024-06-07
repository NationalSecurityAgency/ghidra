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
package ghidra.debug.flatapi;

import java.util.*;

import ghidra.app.services.TraceRmiLauncherService;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public interface FlatDebuggerRmiAPI extends FlatDebuggerAPI {

	/**
	 * Get the trace-rmi launcher service
	 * 
	 * @return the service
	 */
	default TraceRmiLauncherService getTraceRmiLauncherService() {
		return requireService(TraceRmiLauncherService.class);
	}

	/**
	 * Get offers for launching the given program
	 * 
	 * @param program the program, or null for no image
	 * @return the offers
	 */
	default Collection<TraceRmiLaunchOffer> getLaunchOffers(Program program) {
		return getTraceRmiLauncherService().getOffers(program);
	}

	/**
	 * Get offers for launching the current program
	 * 
	 * @return the offers
	 */
	default Collection<TraceRmiLaunchOffer> getLaunchOffers() {
		return getLaunchOffers(getCurrentProgram());
	}

	/**
	 * Get saved offers for launching the given program, ordered by most-recently-saved
	 * 
	 * @param program the program, or null for no image
	 * @return the offers
	 */
	default List<TraceRmiLaunchOffer> getSavedLaunchOffers(Program program) {
		return getTraceRmiLauncherService().getSavedOffers(program);
	}

	/**
	 * Get saved offers for launching the current program, ordered by most-recently-saved
	 * 
	 * @return the offers
	 */
	default List<TraceRmiLaunchOffer> getSavedLaunchOffers() {
		return getSavedLaunchOffers(getCurrentProgram());
	}

	/**
	 * Get the most-recently-saved launch offer for the given program
	 * 
	 * @param program the program, or null for no image
	 * @return the offer
	 * @throws NoSuchElementException if no offer's configuration has been saved
	 */
	default TraceRmiLaunchOffer requireLastLaunchOffer(Program program) {
		List<TraceRmiLaunchOffer> offers = getSavedLaunchOffers(program);
		if (offers.isEmpty()) {
			throw new NoSuchElementException("No saved offers to launch " + program);
		}
		return offers.get(0);
	}

	/**
	 * Get the most-recently-saved launch offer for the current program
	 * 
	 * @return the offer
	 * @throws NoSuchElementException if no offer's configuration has been saved
	 */
	default TraceRmiLaunchOffer requireLastLaunchOffer() {
		return requireLastLaunchOffer(getCurrentProgram());
	}

	/**
	 * Launch the given offer with the default, saved, and/or overridden arguments
	 * 
	 * <p>
	 * If the offer has saved arguments, those will be loaded. Otherwise, the default arguments will
	 * be used. If given, specific arguments can be overridden by the caller. The caller may need to
	 * examine the offer's parameters before overriding any arguments. Conventionally, the argument
	 * displayed as "Image" gives the path to the executable, and "Args" gives the command-line
	 * arguments to pass to the target.
	 * 
	 * @param offer the offer to launch
	 * @param monitor a monitor for the launch stages
	 * @param overrideArgs overridden arguments, which may be empty
	 * @return the launch result, which may indicate errors
	 */
	default LaunchResult launch(TraceRmiLaunchOffer offer, Map<String, ?> overrideArgs,
			TaskMonitor monitor) {
		return offer.launchProgram(monitor, new LaunchConfigurator() {
			@Override
			public Map<String, ?> configureLauncher(TraceRmiLaunchOffer offer,
					Map<String, ?> arguments, RelPrompt relPrompt) {
				if (arguments.isEmpty()) {
					return arguments;
				}
				Map<String, Object> args = new HashMap<>(arguments);
				args.putAll(overrideArgs);
				return args;
			}
		});
	}

	/**
	 * Launch the given offer with the default or saved arguments
	 * 
	 * @param offer the offer to launch
	 * @param monitor a monitor for the launch stages
	 * @return the launch result, which may indicate errors
	 */
	default LaunchResult launch(TraceRmiLaunchOffer offer, TaskMonitor monitor) {
		return launch(offer, Map.of(), monitor);
	}

	/**
	 * Launch the given program with the most-recently-saved offer
	 * 
	 * @param program the program to launch
	 * @param monitor a monitor for the launch stages
	 * @return the launch result, which may indicate errors
	 */
	default LaunchResult launch(Program program, TaskMonitor monitor) {
		return launch(requireLastLaunchOffer(program), monitor);
	}

	/**
	 * Launch the current program with the most-recently-saved offer
	 * 
	 * @param monitor a monitor for the launch stages
	 * @return the launch result, which may indicate errors
	 */
	default LaunchResult launch(TaskMonitor monitor) {
		return launch(requireLastLaunchOffer(), monitor);
	}
}
