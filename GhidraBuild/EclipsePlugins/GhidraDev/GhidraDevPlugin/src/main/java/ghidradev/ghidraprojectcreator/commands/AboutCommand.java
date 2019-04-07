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
package ghidradev.ghidraprojectcreator.commands;

import org.eclipse.core.commands.*;
import org.osgi.framework.FrameworkUtil;
import org.osgi.framework.Version;

import ghidradev.EclipseMessageUtils;

/**
 * Pops up a dialog with information about the plugin.
 */
public class AboutCommand extends AbstractHandler {

	@Override
	public Object execute(ExecutionEvent event) throws ExecutionException {
		Version version = FrameworkUtil.getBundle(getClass()).getVersion();
		StringBuilder message = new StringBuilder();
		message.append("GhidraDev " + version.toString() + "\n\n");
		message.append("Ghidra Development support for Eclipse");
		EclipseMessageUtils.showInfoDialog("About", message.toString());
		return null;
	}
}
