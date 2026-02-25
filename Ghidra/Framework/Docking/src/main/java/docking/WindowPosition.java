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
package docking;

/**
 * An enum used to signal where windows should be placed <b>when shown for the first time.</b>
 * After being shown, a window's location is remembered, so that values is no longer used.
 */
public enum WindowPosition {
	TOP, BOTTOM, LEFT, RIGHT,

	/**
	 * Signals that window should not be placed next to windows in other groups, but should 
	 * be placed into their own window.
	 * <p>
	 * <b>This position is ignored when used with components that share the same group (a.k.a., 
	 * when used as an intragroup positioning item).</b>
	 */
	WINDOW,

	/** 
	 * Signals that windows should be stacked with other windows within  
	 * the same group, appending them at the end of the stack.
	 */
	STACK,

	/**
	 * Signals that windows should be stacked with other windows within
	 * the same group, prepending them at the beginning of the stack.
	 *
	 * NOTE: This should not be used for setDefaultWindowPosition() and
	 * setIntraGroupPosition(), it's just an action code.  Use STACK to
	 * mark the real window position, instead.
	 */
	PREPEND,

	/**
	 * Signals that windows should be pushed between other windows, for
	 * taking a selected window position in the stack.
	 *
	 * NOTE: This should not be used for setDefaultWindowPosition() and
	 * setIntraGroupPosition(), it's just an action code.  Use STACK to
	 * mark the real window position, instead.
	 */
	PUSH,

	/**
	 * Signals that windows are shifting position within the same group
	 * of stacked windows, moving over windows preceding them.
	 *
	 * NOTE: This should not be used for setDefaultWindowPosition() and
	 * setIntraGroupPosition(), it's just an action code.  Use STACK to
	 * mark the real window position, instead.
	 */
	SHIFT_LEFT,

	/**
	 * Signals that windows are shifting position within the same group
	 * of stacked windows, moving over windows following them.
	 *
	 * NOTE: This should not be used for setDefaultWindowPosition() and
	 * setIntraGroupPosition(), it's just an action code.  Use STACK to
	 * mark the real window position, instead.
	 */
	SHIFT_RIGHT
}
