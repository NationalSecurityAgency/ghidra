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
package ghidra.feature.vt.gui.plugin;

import ghidra.framework.plugintool.util.PluginPackage;

import javax.swing.Icon;

import resources.ResourceManager;

public class VersionTrackingPluginPackage extends PluginPackage {
	public static final String NAME = "Version Tracking";
	public static final Icon ICON = ResourceManager.loadImage("images/start-here.png");
	
	public VersionTrackingPluginPackage() {
		super(NAME, ICON, 
		    "These plugins provide feature for performing version tracking between programs." );
	}

}
