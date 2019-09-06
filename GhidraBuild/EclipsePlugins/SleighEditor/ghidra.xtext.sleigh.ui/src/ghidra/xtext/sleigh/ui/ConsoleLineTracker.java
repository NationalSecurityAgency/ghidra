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
package ghidra.xtext.sleigh.ui;

import org.eclipse.debug.core.model.IProcess;
import org.eclipse.debug.ui.console.IConsole;
import org.eclipse.debug.ui.console.IConsoleLineTracker;
import org.eclipse.jface.text.IRegion;

public class ConsoleLineTracker implements IConsoleLineTracker {

	@Override
	public void init(IConsole console) {
		IProcess process = console.getProcess();

		System.out.println(process.getLabel());
	}

	@Override
	public void lineAppended(IRegion line) {
		System.out.println(line.toString());
	}

	@Override
	public void dispose() {
		// TODO Auto-generated method stub

	}

}
