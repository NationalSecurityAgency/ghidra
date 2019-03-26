/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.listing.Program;

import java.lang.ref.WeakReference;

/**
 * Plugin event class for notification of programs being created, opened, or
 * closed.
 *
 */
public class ProgramActivatedPluginEvent extends PluginEvent {

	static final String NAME = "Program Activated";
//	static final String TOOL_EVENT_NAME = "Program Activated";
//
//	static {
//        registerPluginEventMapping(OpenProgramPluginEvent.class, TOOL_EVENT_NAME);
//    }
   
    private WeakReference<Program> newProgramRef;

    /**
     * Construct a new plugin event.
     * @param source name of the plugin that created this event
     * @param activeProgram the program associated with this event
     */
    public ProgramActivatedPluginEvent(String source, Program activeProgram) {
        super(source, NAME);
        this.newProgramRef = new WeakReference<Program>(activeProgram);
    }

    /**
     * Return the new activated program. May be null.
     * @return null if the event if for a program closing.
     */
    public Program getActiveProgram () {
        return newProgramRef.get();
    }

}
