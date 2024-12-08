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
package ghidra.app.util.task;

import ghidra.app.plugin.core.progmgr.ProgramLocator;
import ghidra.program.model.listing.Program;

public class OpenProgramRequest {
	private final ProgramLocator locator;
	private final Program program;
	private final Object consumer;

	public OpenProgramRequest(Program program, ProgramLocator locator, Object consumer) {
		this.program = program;
		this.locator = locator;
		this.consumer = consumer;
	}

	/**
	 * Get the open Program instance which corresponds to this open request.
	 * @return program instance or null if never opened.
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Release opened program.  This must be done once, and only once, on a successful 
	 * open request.  If handing ownership off to another consumer, they should be added
	 * as a program consumer prior to invoking this method.  Releasing the last consumer
	 * will close the program instance.
	 */
	public void release() {
		if (program != null) {
			program.release(consumer);
		}
	}

	public ProgramLocator getLocator() {
		return locator;
	}
}
