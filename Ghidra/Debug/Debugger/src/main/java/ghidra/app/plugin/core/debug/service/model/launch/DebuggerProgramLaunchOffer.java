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
package ghidra.app.plugin.core.debug.service.model.launch;

import java.util.concurrent.CompletableFuture;

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.util.task.TaskMonitor;

/**
 * An offer to launch a program with a given mechanism
 * 
 * <p>
 * Typically each offer is configured with the program it's going to launch, and knows how to work a
 * specific connector and platform to obtain a target executing the program's image. The mechanisms
 * may vary wildly from platform to platform.
 */
public interface DebuggerProgramLaunchOffer {

	/**
	 * Launch the program using the offered mechanism
	 * 
	 * @param monitor a monitor for progress and cancellation
	 * @param prompt if the user should be prompted to confirm launch parameters
	 * @return a future which completes when the program is launched
	 */
	CompletableFuture<Void> launchProgram(TaskMonitor monitor, boolean prompt);

	/**
	 * A name so that this offer can be recognized later
	 * 
	 * <p>
	 * The name is saved to configuration files, so that user preferences and priorities can be
	 * memorized. The opinion will generate each offer fresh each time, so it's important that the
	 * "same offer" have the same configuration name. Note that the name <em>cannot</em> depend on
	 * the program name, but can depend on the model factory and program language and/or compiler
	 * spec. This name cannot contain semicolons ({@ code ;}).
	 * 
	 * @return the configuration name
	 */
	String getConfigName();

	/**
	 * Get the icon displayed in the UI for this offer
	 * 
	 * <p>
	 * Don't override this except for good reason. If you do override, please return a variant that
	 * still resembles this icon, e.g., just overlay on this one.
	 * 
	 * @return the icon
	 */
	default Icon getIcon() {
		return DebuggerResources.ICON_DEBUGGER;
	}

	/**
	 * Get the text display on the parent menu for this offer
	 * 
	 * <p>
	 * Unless there's good reason, this should always be "Debug [executablePath]".
	 * 
	 * @return the title
	 */
	String getMenuParentTitle();

	/**
	 * Get the text displayed on the menu for this offer
	 * 
	 * @return the title
	 */
	String getMenuTitle();

	/**
	 * Get the text displayed if the user will not be prompted
	 * 
	 * <p>
	 * Sometimes when "the last options" are being used without prompting, it's a good idea to
	 * remind the user what those options were.
	 * 
	 * @return the title
	 */
	default String getQuickTitle() {
		return getMenuTitle();
	}

	/**
	 * Get the text displayed on buttons for this offer
	 * 
	 * @return the title
	 */
	default String getButtonTitle() {
		return getMenuParentTitle() + " " + getQuickTitle();
	}

	/**
	 * Get the default priority (position in the menu) of the offer
	 * 
	 * <p>
	 * Note that greater priorities will be listed first, with the greatest being the default "quick
	 * launch" offer.
	 * 
	 * @return the priority
	 */
	default int defaultPriority() {
		return 50;
	}
}
