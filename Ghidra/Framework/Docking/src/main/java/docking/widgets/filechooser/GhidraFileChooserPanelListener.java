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
package docking.widgets.filechooser;

import java.io.File;

/**
 * A listener for notifying when the file in the file chooser panel have changed.
 * 
 */
public interface GhidraFileChooserPanelListener {
    /**
     * Notification the file change.
     * @param file the new file
     */
    public void fileChanged(File file);
    /**
     * Notification that a new file was dropped on the panel.
     * @param file the new file that was dropped
     */
    public void fileDropped(File file);
}
