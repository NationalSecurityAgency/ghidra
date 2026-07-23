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

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.listing.Program;

/**
 * {@link Plugin} event class for notification of an "Add To Program" occurring
 */
public class ProgramAddedToPluginEvent extends PluginEvent {

	static final String NAME = "Program Added To";

	private WeakReference<Program> programRef;
	private boolean analyze;

	/**
	 * Construct a new {@link ProgramAddedToPluginEvent}
	 * 
	 * @param source name of the {@link Plugin} that created this event
	 * @param p the {@link Program} associated with this event
	 * @param analyze True if this even should lead to analysis; otherwise, false
	 */
	public ProgramAddedToPluginEvent(String source, Program p, boolean analyze) {
		super(source, NAME);
		this.programRef = new WeakReference<>(p);
		this.analyze = analyze;
	}

	/**
	 * {@return the {@link Program} that has just been added to, or {@code null} if the method is 
	 * called some time after the original event notification}
	 */
	public Program getProgram() {
		return programRef.get();
	}

	/**
	 * {@return whether or not to do analysis as a result this event}
	 */
	public boolean analyze() {
		return analyze;
	}
}
