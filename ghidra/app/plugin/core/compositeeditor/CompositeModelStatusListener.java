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
 * Composite Viewer Model status information change listener interface.
 */
public interface CompositeModelStatusListener {
	/**
	 * Notification that the CompositeViewerModel's status information has changed.
	 *
	 * @param message the information to provide to the user.
     * @param beep true indicates an audible beep is suggested.
	 */
	 void statusChanged(String message, boolean beep);
}
