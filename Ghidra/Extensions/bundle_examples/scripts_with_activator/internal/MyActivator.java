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
package internal;

import org.osgi.framework.BundleContext;

import docking.action.DockingAction;
import ghidra.app.plugin.core.osgi.GhidraBundleActivator;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.Swing;

/**
 * An example BundleActivator that manages a {@link DockingAction}.
 */
public class MyActivator extends GhidraBundleActivator {

	private static PluginTool storedTool;
	private static DockingAction storedAction;

	/**
	 * add {@code action} to {@code tool} and store both to remove later.
	 * 
	 * Note: this can be used exactly once per bundle lifecycle, i.e. between start & stop.
	 * 
	 * @param tool the tool to add {@code action} to 
	 * @param action the action to add to {@code tool}
	 * @return false if this add operation has already been performed
	 */
	public static boolean addAction(PluginTool tool, DockingAction action) {
		if (storedTool != null || storedAction != null) {
			return false;
		}
		storedTool = tool;
		storedAction = action;
		Swing.runNow(() -> {
			storedTool.addAction(storedAction);
		});
		return true;
	}

	/**
	 * Called by Ghidra when bundle is activated.
	 * 
	 * @param bundleContext the context for this bundle
	 * @param api placeholder for future Ghidra API
	 */
	@Override
	protected void start(BundleContext bundleContext, Object api) {
		if (storedAction != null) {
			Msg.showError(this, null, "Activator error!", "storedAction non-null on bundle start!");
		}
	}

	/**
	 * Called by Ghidra when bundle is deactivated.
	 * 
	 * @param bundleContext the context for this bundle
	 * @param api placeholder for future Ghidra API
	 */
	@Override
	protected void stop(BundleContext bundleContext, Object api) {
		if (storedAction != null) {
			storedAction.dispose();
			if (storedTool == null) {
				Msg.showError(this, null, "Activator error!", "storedTool is null!");
			}
			else {
				storedTool.removeAction(storedAction);
			}
			storedTool = null;
			storedAction = null;
		}
	}
}
