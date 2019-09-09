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
package ghidra.xtext.sleigh.ui.console;

import org.eclipse.debug.core.model.IProcess;
import org.eclipse.debug.ui.console.IConsole;
import org.eclipse.debug.ui.console.IConsoleLineTracker;
import org.eclipse.jface.text.IRegion;

//import org.eclipse.ant.internal.ui.launchConfigurations.TaskLinkManager;

public class ConsoleLineTracker implements IConsoleLineTracker {

	private IConsole fConsole;
	
	/**
	 * @see org.eclipse.debug.ui.console.IConsoleLineTracker#init(org.eclipse.debug.ui.console.IConsole)
	 */
	@Override
	public void init(IConsole console) {
		IProcess process = console.getProcess();
	}

	@Override
	public void lineAppended(IRegion line) {
//		TaskLinkManager.processNewLine(fConsole, line);
	}

	@Override
	public void dispose() {
		fConsole = null;
	}

}
