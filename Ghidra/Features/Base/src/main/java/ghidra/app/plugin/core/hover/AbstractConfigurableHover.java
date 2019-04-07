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
package ghidra.app.plugin.core.hover;

import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;

/**
 * A listing or decompiler hover that employs some degree of configurability.
 */
public abstract class AbstractConfigurableHover extends AbstractHover implements ConfigurableHover {

	protected ToolOptions options;

	public AbstractConfigurableHover(PluginTool tool, int priority) {
		super(tool, priority);
		initializeOptions();
	}

	@Override
	public void dispose() {
		if (options != null) {
			options.removeOptionsChangeListener(this);
			options = null;
		}
	}

	@Override
	public void optionsChanged(ToolOptions theOptions, String optionName, Object oldValue, Object newValue) {
		setOptions(theOptions, optionName);
	}

}
