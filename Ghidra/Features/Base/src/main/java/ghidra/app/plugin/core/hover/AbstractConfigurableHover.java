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

import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Disposable;

/**
 * A listing or decompiler hover that employs some degree of configurability.
 */
public abstract class AbstractConfigurableHover extends AbstractHover
		implements Disposable, OptionsChangeListener {

	protected ToolOptions options;

	public AbstractConfigurableHover(PluginTool tool, int priority) {
		super(tool, priority);
		initializeOptions();
	}

	protected abstract String getName();

	protected abstract String getDescription();

	protected abstract String getOptionsCategory();

	@Override
	public void dispose() {
		if (options != null) {
			options.removeOptionsChangeListener(this);
			options = null;
		}
	}

	@Override
	public void optionsChanged(ToolOptions theOptions, String optionName, Object oldValue,
			Object newValue) {
		setOptions(theOptions, optionName);
	}

	public void initializeOptions() {
		options = tool.getOptions(getOptionsCategory());

		String hoverName = getName();
		options.registerOption(hoverName, true, null, getDescription());
		setOptions(options, hoverName);
		options.addOptionsChangeListener(this);
	}

	public void setOptions(Options options, String optionName) {
		String hoverName = getName();
		if (optionName.equals(hoverName)) {
			enabled = options.getBoolean(hoverName, true);
		}
	}
}
