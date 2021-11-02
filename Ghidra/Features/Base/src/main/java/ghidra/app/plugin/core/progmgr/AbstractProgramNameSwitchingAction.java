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

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.context.ProgramActionContext;
import ghidra.program.model.listing.Program;

/**
 * Abstract base class for program actions that change their menu name depending on the the active
 * program. Note that actions that derived from this class only work on programs that are
 * globally managed by Ghidra and not opened and managed by individual plugins. If the action 
 * context should happen to contain a non-global managed program, the tool's concept of the 
 * current active program will be used as target of this action instead.
 */
public abstract class AbstractProgramNameSwitchingAction extends DockingAction {

	protected ProgramManagerPlugin plugin;
	protected Program lastContextProgram;

	/**
	 * Constructor
	 * @param plugin the ProgramManagerPlugin (i.e. the global Ghidra manager for programs)
	 * @param name the name of the action
	 * programs
	 */
	public AbstractProgramNameSwitchingAction(ProgramManagerPlugin plugin, String name) {
		super(name, plugin.getName());
		this.plugin = plugin;
		addToWindowWhen(ProgramActionContext.class);
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		Program program = getProgram(context);
		if (program != lastContextProgram) {
			lastContextProgram = program;
			programChanged(program);
		}
		return true;
	}

	@Override
	public final boolean isEnabledForContext(ActionContext context) {
		return isEnabledForContext(getProgram(context));

	}

	protected boolean isEnabledForContext(Program program) {
		return program != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Program program = getProgram(context);
		if (program != null) {
			actionPerformed(program);
		}
	}

	protected abstract void actionPerformed(Program program);

	protected abstract void programChanged(Program program);

	/**
	 * Gets the program for the given context. The actions that derive from this class only
	 * work on programs that are globally managed by Ghidra. So if the program from the context
	 * is not managed by Ghidra, then just use the current program that is managed.
	 * @param context the action context from which to get the program
	 * @return the appropriate program to use for this action.
	 */
	protected Program getProgram(ActionContext context) {
		if (context instanceof ProgramActionContext) {
			Program program = ((ProgramActionContext) context).getProgram();
			if (plugin.isManaged(program)) {
				return program;
			}
			// otherwise, just return the global current program.
		}
		return plugin.getCurrentProgram();
	}
}
