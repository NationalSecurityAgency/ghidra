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
package ghidra.app.services;

import java.util.List;

import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.TargetPublicationListener;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.trace.model.Trace;

@ServiceInfo(
	description = """
			A service for tracking a set of published targets. Services capable of creating targets
			should publish them using this service.
			""",
	defaultProviderName = "ghidra.app.plugin.core.debug.service.target.DebuggerTargetServicePlugin")
public interface DebuggerTargetService {
	/**
	 * Publish a target to the service and its listeners
	 * 
	 * @param target the new target
	 */
	void publishTarget(Target target);

	/**
	 * Withdraw a target from the service and its listeners
	 * 
	 * @param target the (presumably invalidated) target
	 */
	void withdrawTarget(Target target);

	/**
	 * Get a list of all published targets
	 * 
	 * @return the list in no particular order
	 */
	List<Target> getPublishedTargets();

	/**
	 * Get the target for the given trace
	 * 
	 * @param trace the trace
	 * @return the target, or null if there is no such target
	 */
	Target getTarget(Trace trace);

	/**
	 * Add a listener for target publication and withdrawal events
	 * 
	 * @param listener the listener
	 */
	void addTargetPublicationListener(TargetPublicationListener listener);

	/**
	 * Remove a listener for target publication and withdrawal events
	 * 
	 * @param listener the listener
	 */
	void removeTargetPublicationListener(TargetPublicationListener listener);
}
