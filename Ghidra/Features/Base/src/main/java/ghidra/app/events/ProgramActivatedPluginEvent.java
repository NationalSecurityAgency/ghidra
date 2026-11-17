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
package ghidra.app.events;

import java.lang.ref.WeakReference;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.listing.Program;

/**
 * Plugin event class for notification of programs being activated.
 * <P>
 * The framework may fire this event with a {@code null} program. This symbolizes a program 
 * de-actived event. A de-activate event is not fired symmetrically with an activated event. It is
 * up to plugins to handle receiving an activated event without receiving a de-activated event.
 * See {@link ProgramPlugin}.
 */
public class ProgramActivatedPluginEvent extends PluginEvent {

	private static final String NAME = "Program Activated";

	protected WeakReference<Program> newProgramRef;

	/**
	 * Construct a new plugin event.
	 * @param source name of the plugin that created this event
	 * @param activeProgram the program associated with this event
	 * @deprecated Clients should not be constructing and firing this event.  Instead clients should
	 *             be using {@link ProgramManager#setCurrentProgram(Program)}.
	 */
	@Deprecated(since = "12.3")

	public ProgramActivatedPluginEvent(String source, Program activeProgram) {
		super(source, NAME);
		this.newProgramRef = new WeakReference<Program>(activeProgram);
	}

	protected ProgramActivatedPluginEvent(String source, String name, Program activeProgram) {
		super(source, name);
		this.newProgramRef = new WeakReference<Program>(activeProgram);
	}

	/**
	 * Returns the {@link Program} that has is being activated. This method may return null for an 
	 * activated event, but it is unlikely. In this case, it will only return null if the program 
	 * has been closed and is no longer in use. 
	 * @return the {@link Program} that has just been activated
	 */
	public Program getActiveProgram() {
		return newProgramRef.get();
	}

}
