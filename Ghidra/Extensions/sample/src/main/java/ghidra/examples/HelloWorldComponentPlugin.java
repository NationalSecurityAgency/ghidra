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
package ghidra.examples;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

/**
  * This Plugin demonstrates how to add a GUI component to the tool and add a local action (action that
  * only applies to particular component).
  */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Hello World",
	description = "Sample plugin to demonstrate how to write a plugin with a dockable GUI component."
)
//@formatter:on
public class HelloWorldComponentPlugin extends Plugin {
	private HelloWorldComponentProvider provider;

	/** 
	  * Constructor - Setup the plugin
	  */
	public HelloWorldComponentPlugin(PluginTool tool) {
		super(tool);

		provider = new HelloWorldComponentProvider(tool, getName());
	}

	@Override
	public void dispose() {
		provider.setVisible(false);

		// The plugin is getting removed from the tool; do any clean up
		// here and release resources if necessary.
	}
}
