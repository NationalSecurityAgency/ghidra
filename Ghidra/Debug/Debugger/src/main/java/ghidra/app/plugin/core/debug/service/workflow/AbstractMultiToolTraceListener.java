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
package ghidra.app.plugin.core.debug.service.workflow;

import java.util.HashSet;
import java.util.Set;

import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceDomainObjectListener;

public class AbstractMultiToolTraceListener extends TraceDomainObjectListener {
	protected final Trace trace;
	protected final Set<PluginTool> openIn = new HashSet<>();

	public AbstractMultiToolTraceListener(Trace trace) {
		this.trace = trace;
	}

	protected void init() {
		trace.addListener(this);
	}

	protected void dispose() {
		trace.removeListener(this);
	}

	protected void openedBy(PluginTool tool) {
		openIn.add(tool);
	}

	protected boolean closedBy(PluginTool tool) {
		openIn.remove(tool);
		return openIn.isEmpty();
	}
}
