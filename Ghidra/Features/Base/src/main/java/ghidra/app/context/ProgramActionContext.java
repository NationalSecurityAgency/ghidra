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
package ghidra.app.context;

import ghidra.program.model.listing.Program;
import docking.ActionContext;
import docking.ComponentProvider;

public class ProgramActionContext extends ActionContext {
	protected final Program program;

	
	public ProgramActionContext(ComponentProvider provider, Program program) {
		this(provider, program, null);
	}
	
	public ProgramActionContext(ComponentProvider provider, Program program, Object contextObject) {
		super(provider, contextObject);
		this.program = program;
	}

	/**
	 * @return Returns the program.
	 */
	public Program getProgram() {
		return program;
	}
}
