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
package ghidra.app.plugin.core.progmgr;

import java.awt.Component;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import ghidra.program.model.listing.Program;

/**
 * Action context for program tabs
 */
public class ProgramTabActionContext extends DefaultActionContext {
	public ProgramTabActionContext(ComponentProvider provider, Program program, Component source) {
		super(provider, program, source);
	}

	/**
	 * Returns the program for the tab that was clicked on.
	 * @return the program for the tab that was clicked on
	 */
	public Program getProgram() {
		return (Program) getContextObject();
	}
}
