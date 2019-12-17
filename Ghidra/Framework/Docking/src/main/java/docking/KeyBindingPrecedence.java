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
 * An enum that holds the values for order of keybinding precedence, in order from 
 * highest priority to lowest.  For a more detailed description of how Ghidra processes
 * key events see <code>ghidra.KeyBindingOverrideKeyDispatcher.dispatchKeyEvent(KeyEvent)</code>
 */
public enum KeyBindingPrecedence {
    
    /** Actions at this level will be processed before all others, including Java components'.  */
    ReservedActionsLevel,
    
	/** Actions with this precedence will be processed before key listener on Java components. */
	KeyListenerLevel,
	
	/** Actions with this precedence will be processed before actions on Java components. */
	ActionMapLevel,
	
	/** This level of precedence is the default level of precedence and gets processed after
	 *  Java components' key listeners and actions.  */
	DefaultLevel
}
