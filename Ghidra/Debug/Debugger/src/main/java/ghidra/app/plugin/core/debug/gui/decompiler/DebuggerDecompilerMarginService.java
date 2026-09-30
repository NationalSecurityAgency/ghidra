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
package ghidra.app.plugin.core.debug.gui.decompiler;

import ghidra.framework.plugintool.ServiceInfo;

/**
 * A service for displaying Debugger icons, e.g., breakpoints and the tracked location, in a single
 * margin of the Decompiler
 */
@ServiceInfo(
	defaultProvider = DebuggerDecompilerMarginServicePlugin.class,
	description = "Display Debugger icons in the Decompiler's margin")
public interface DebuggerDecompilerMarginService {
	/**
	 * Add a source of icons to the margin
	 *
	 * @param source the source
	 */
	void addIconSource(DecompilerMarginIconSource source);

	/**
	 * Remove a source of icons from the margin
	 *
	 * @param source the source
	 */
	void removeIconSource(DecompilerMarginIconSource source);

	/**
	 * Notify the margin that the icons of one or more sources have changed
	 */
	void iconsChanged();
}
