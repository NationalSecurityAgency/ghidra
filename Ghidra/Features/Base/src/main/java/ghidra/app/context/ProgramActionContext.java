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
package ghidra.app.context;

import java.awt.Component;
import java.awt.KeyboardFocusManager;

import docking.ComponentProvider;
import docking.DefaultActionContext;
import ghidra.program.model.listing.Program;

public class ProgramActionContext extends DefaultActionContext {
	protected final Program program;

	public ProgramActionContext(ComponentProvider provider, Program program) {
		this(provider, program, null);
	}

	public ProgramActionContext(ComponentProvider provider, Program program,
			Component sourceComponent) {
		this(provider, program, sourceComponent, sourceComponent);
	}

	public ProgramActionContext(ComponentProvider provider, Program program,
			Component sourceComponent, Object contextObject) {
		super(provider, contextObject, sourceComponent);
		this.program = program;

		// the case where the first constructor is called, which does not specify the component
		if (sourceComponent == null) {
			KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
			setSourceObject(kfm.getFocusOwner());
		}
	}

	public Program getProgram() {
		return program;
	}

	/**
	 * Returns true if the program in this context is the globally active program in the tool.  This
	 * is generally true for all context.  Some context providers may be working with a different
	 * program than the active program or they may be using the active program with restricted 
	 * address views.  In this latter case, this method should return false.
	 * @return true if the program is the active program; false means the program may not be the 
	 *         active program
	 */
	public boolean isActiveProgram() {
		return true;
	}
}
