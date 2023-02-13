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

import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.listing.Program;

/**
 * Plugin event class for notification that plugin first pass processing of a newly activated 
 * program is complete. More specifically, all plugins have received and had a chance
 * to react to a {@link ProgramActivatedPluginEvent}.
 */
public class ProgramPostActivatedPluginEvent extends PluginEvent {

	static final String NAME = "Post Program Activated";
	private WeakReference<Program> newProgramRef;

	/**
	 * Constructor
	 * @param source name of the plugin that created this event
	 * @param activeProgram the program that has been activated
	 */
	public ProgramPostActivatedPluginEvent(String source, Program activeProgram) {
		super(source, NAME);
		this.newProgramRef = new WeakReference<Program>(activeProgram);
	}

	/**
	 * Return the new activated program. May be null.
	 * @return null if the event if for a program closing.
	 */
	public Program getActiveProgram() {
		return newProgramRef.get();
	}

}
