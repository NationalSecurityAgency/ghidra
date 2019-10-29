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
package ghidra.framework.plugintool.testplugins;

import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;

/**
 * Test plugin for {@link PluginManagerTest#testDiamond()}
 * <pre>
 *      A
 *    /   \
 *   B <---C--------------- you are here
 *    \   /
 *      D
 * </pre>
 */
//@formatter:off
@PluginInfo(status = PluginStatus.HIDDEN,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.UNMANAGED,
	shortDescription = "Test plugin",
	description = "Test plugin",
	servicesProvided = DiamondServiceB.class,
	servicesRequired = DiamondServiceD.class)
//@formatter:on
public class DiamondPluginB extends Plugin implements DiamondServiceB, TestingPlugin {

	public DiamondPluginB(PluginTool tool) {
		super(tool);
	}

}
