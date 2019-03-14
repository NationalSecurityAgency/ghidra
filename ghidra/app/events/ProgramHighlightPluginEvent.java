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

import java.lang.ref.WeakReference;

import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

/**
 *  Plugin event generated when the highlight in a program changes.
 */
public final class ProgramHighlightPluginEvent extends PluginEvent { 
    public static final String NAME = "ProgramHighlight";

    private ProgramSelection highlight;
    private WeakReference<Program> programRef;

	/**
	 * Construct a new event.
	 * @param src name of the plugin that generated the event
	 * @param hl Program selection containing the selected address set.
	 * @param program program being highlighted
	 */
    public ProgramHighlightPluginEvent(String src,ProgramSelection hl,
            Program program) {
        super(src, NAME);
        this.highlight = hl;
        this.programRef = new WeakReference<Program>(program);
    }

	/**
	 * Returns the program selection contained in this event.
	 * @return ProgramSelection contained in this event.
	 */
    public ProgramSelection getHighlight() {
        return highlight;
    }

    /**
     * Returns the Program object that the highlight refers to. 
     */
    public Program getProgram() {
        return programRef.get();
    }
}
