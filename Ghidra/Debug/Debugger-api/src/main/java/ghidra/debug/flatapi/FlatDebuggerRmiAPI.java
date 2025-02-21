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
import java.util.Map.Entry;

import ghidra.app.services.TraceRmiLauncherService;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public interface FlatDebuggerRmiAPI extends FlatDebuggerAPI {

    /**
     * Retrieves the trace-RMI launcher service instance.
     *
     * @return the trace-RMI launcher service
     */
    default TraceRmiLauncherService getTraceRmiLauncherService() {
        return requireService(TraceRmiLauncherService.class);
    }

    /**
     * Gets the launch offers available for the specified program.
     *
     * @param program the program for which to get launch offers, or null for no image
     * @return a collection of launch offers
     */
    default Collection<TraceRmiLaunchOffer> getLaunchOffers(Program program) {
        return getTraceRmiLauncherService().getOffers(program);
    }

    /**
     * Gets the launch offers available for the currently loaded program.
     *
     * @return a collection of launch offers for the current program
     */
    default Collection<TraceRmiLaunchOffer> getLaunchOffers() {
        return getLaunchOffers(getCurrentProgram());
    }

    /**
     * Retrieves saved launch offers for the specified program, ordered by most recently saved.
     *
     * @param program the program for which to get saved launch offers, or null for no image
     * @return a list of saved launch offers
     */
    default List<TraceRmiLaunchOffer> getSavedLaunchOffers(Program program) {
        return getTraceRmiLauncherService().getSavedOffers(program);
    }

    /**
     * Retrieves saved launch offers for the currently loaded program, ordered by most recently saved.
     *
     * @return a list of saved launch offers for the current program
     */
    default List<TraceRmiLaunchOffer> getSavedLaunchOffers() {
        return getSavedLaunchOffers(getCurrentProgram());
    }

    /**
     * Retrieves the most recently saved launch offer for the specified program.
     *
     * @param program the program for which to retrieve the last saved offer, or null for no image
     * @return the most recently saved launch offer
     * @throws NoSuchElementException if no offers are saved for the specified program
     */
    default TraceRmiLaunchOffer requireLastLaunchOffer(Program program) {
        List<TraceRmiLaunchOffer> offers = getSavedLaunchOffers(program);
        if (offers.isEmpty()) {
            throw new NoSuchElementException("No saved offers to launch " + program);
        }
        return offers.get(0);
    }

    /**
     * Retrieves the most recently saved launch offer for the currently loaded program.
     *
     * @return the most recently saved launch offer for the current program
     * @throws NoSuchElementException if no offers are saved for the current program
     */
    default TraceRmiLaunchOffer requireLastLaunchOffer() {
        return requireLastLaunchOffer(getCurrentProgram());
    }

    /**
     * Launches the specified offer with default, saved, and/or overridden arguments.
     *
     * @param offer the launch offer to execute
     * @param overrideArgs a map of arguments to override, which may be empty
     * @param monitor a monitor to track the launch stages
     * @return the result of the launch, which may indicate errors
     */
    default LaunchResult launch(TraceRmiLaunchOffer offer, Map<String, ?> overrideArgs, TaskMonitor monitor) {
        return offer.launchProgram(monitor, new LaunchConfigurator() {
            @Override
            public Map<String, ValStr<?>> configureLauncher(TraceRmiLaunchOffer offer,
                                                             Map<String, ValStr<?>> arguments, RelPrompt relPrompt) {
                Map<String, ValStr<?>> args = new HashMap<>(arguments);
                overrideArgs.forEach((key, value) -> args.put(key, ValStr.from(value)));
                return args;
            }
        });
    }

    /**
     * Launches the specified offer using default or saved arguments.
     *
     * @param offer the launch offer to execute
     * @param monitor a monitor to track the launch stages
     * @return the result of the launch, which may indicate errors
     */
    default LaunchResult launch(TraceRmiLaunchOffer offer, TaskMonitor monitor) {
        return launch(offer, Collections.emptyMap(), monitor);
    }

    /**
     * Launches the specified program using the most recently saved launch offer.
     *
     * @param program the program to launch
     * @param monitor a monitor to track the launch stages
     * @return the result of the launch, which may indicate errors
     */
    default LaunchResult launch(Program program, TaskMonitor monitor) {
        return launch(requireLastLaunchOffer(program), monitor);
    }

    /**
     * Launches the currently loaded program using the most recently saved launch offer.
     *
     * @param monitor a monitor to track the launch stages
     * @return the result of the launch, which may indicate errors
     */
    default LaunchResult launch(TaskMonitor monitor) {
        return launch(requireLastLaunchOffer(), monitor);
    }
}
