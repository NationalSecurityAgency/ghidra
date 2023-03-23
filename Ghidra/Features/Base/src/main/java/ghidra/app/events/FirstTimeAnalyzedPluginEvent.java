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
 * Plugin event class for notification of when programs have completed being analyzed for the first 
 * time.
 */
public class FirstTimeAnalyzedPluginEvent extends PluginEvent {
	public static final String EVENT_NAME = "FirstTimeAnalyzed";

	private WeakReference<Program> programRef;

	/**
	 * Constructor
	 * @param sourceName source name of the plugin that created this event
	 * @param program the program that has been analyzed for the first time
	 */
	public FirstTimeAnalyzedPluginEvent(String sourceName, Program program) {
		super(sourceName, EVENT_NAME);
		this.programRef = new WeakReference<Program>(program);
	}

	/**
	 * Returns the {@link Program} that has just been analyzed for the first time. This method
	 * can return null, but only if the program has been closed and is no longer in use which
	 * can't happen if the method is called during the original event notification.
	 * @return the {@link Program} that has just been analyzed for the first time.
	 */
	public Program getProgram() {
		return programRef.get();
	}
}
