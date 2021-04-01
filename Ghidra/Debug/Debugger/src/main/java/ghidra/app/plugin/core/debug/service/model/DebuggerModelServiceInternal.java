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
package ghidra.app.plugin.core.debug.service.model;

import java.io.IOException;
import java.util.Collection;

import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.mapping.DebuggerTargetTraceMapper;
import ghidra.app.services.*;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.lifecycle.Internal;
import ghidra.util.Swing;

/**
 * Specifies additional methods on the model service which are available for internal testing
 * purposes only.
 */
@Internal
public interface DebuggerModelServiceInternal extends DebuggerModelService {
	/**
	 * Force the set of factory instances to be that given
	 * 
	 * This exists for testing the factory change listeners. A test depending on a controlled
	 * collection of model factories must invoke this method before said test. Conventionally, it is
	 * the responsibility of each test to ensure its own preconditions are met. For a test depending
	 * on classpath-discovered factories, see {@link #refreshFactoryInstances()}.
	 * 
	 * @param factories the forced set of factories
	 * @see #refreshFactoryInstances()
	 */
	void setModelFactories(Collection<DebuggerModelFactory> factories);

	/**
	 * Set the model factories back to those found on the classpath
	 * 
	 * This exists for testing the factory change listeners. A test depending on
	 * classpath-discovered factories must invoke this method. It must consider that a previous test
	 * may have overridden the factories using {@link #setModelFactories(Collection)}.
	 * Conventionally, it is the responsibility of each test to ensure its own preconditions are
	 * met. Tests using {@link #setModelFactories(Collection)} are <em>not</em> required to restore
	 * the classpath-discovered factories.
	 * 
	 * @see #setModelFactories(Collection)
	 */
	void refreshFactoryInstances();

	/**
	 * Start and open a new trace on the given target
	 *
	 * Starts a new trace, and opens it in the tool
	 * 
	 * @see #recordTarget(TargetObject)
	 * @param traceManager the manager for the tool in which to activate the trace
	 */
	TraceRecorder recordTargetAndActivateTrace(TargetObject target,
			DebuggerTargetTraceMapper mapper, DebuggerTraceManagerService traceManager)
			throws IOException;

	/**
	 * Set the active model
	 * 
	 * @param model the new active model
	 * @return true if changed, false otherwise (including if its already the active model)
	 */
	boolean doActivateModel(DebuggerObjectModel model);

	/**
	 * Fire a model-activation event
	 */
	default void fireModelActivatedEvent(DebuggerObjectModel model) {
		firePluginEvent(new ModelActivatedPluginEvent(getName(), model));
	}

	/**
	 * Fire an object-focus event
	 * 
	 * @param focused the focused object
	 */
	default void fireFocusEvent(TargetObject focused) {
		Swing.runIfSwingOrRunLater(
			() -> firePluginEvent(new ModelObjectFocusedPluginEvent(getName(), focused)));
	}

	/**
	 * Fire a recorder-advanced event
	 * 
	 * @param recorder the recorder that advanced
	 * @param snap the snap to which it advanced
	 */
	default void fireSnapEvent(TraceRecorder recorder, long snap) {
		// firePluginEvent uses Swing.runNow, and I can't wait here.
		// Especially since the swing thread gets real busy during a step
		Swing.runIfSwingOrRunLater(
			() -> firePluginEvent(new TraceRecorderAdvancedPluginEvent(getName(), recorder, snap)));
	}

	// Impl should inherit from Plugin
	String getName();

	// Impl should inherit from Plugin
	void firePluginEvent(PluginEvent event);

	@Override
	default void activateModel(DebuggerObjectModel model) {
		if (doActivateModel(model)) {
			fireModelActivatedEvent(model);
		}
	}

	/**
	 * Implement {@link #recordTargetPromptOffers(TargetObject)} using the given plugin tool
	 * 
	 * @param t the plugin tool (front-end or tool containing proxy)
	 * @param target the target to record
	 * @return a future which completes with the resulting recorder, unless cancelled
	 */
	TraceRecorder doRecordTargetPromptOffers(PluginTool t, TargetObject target);
}
