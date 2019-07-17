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
package ghidra.app.plugin.core.compositeeditor;

/**
 * Composite Editor Lock change listener interface.
 * This has a notification method for the lock/unlock mode of the 
 * composite data editor. The lock/unlock mode controls whether or 
 * not the size of the composite data type being edited can change.
 */
public interface CompositeEditorLockListener {
    // Definitions of the types of state changes that can occur.
    public static final int EDITOR_LOCKED = 1;
    public static final int EDITOR_UNLOCKED = 2;

    /**
     * Called whenever the composite data type editor lock/unlock state changes.
     * Whether the editor is in locked or unlocked mode.
     *
     * @param type the type of state change: EDITOR_LOCKED, EDITOR_UNLOCKED.
     */
    public void lockStateChanged(int type);
}
