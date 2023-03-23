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
package ghidra.framework.model;

import java.net.URL;

/**
 * {@code ProjectViewListener} provides a listener interface for tracking project views added
 * and removed from the associated project. 
 * <BR>
 * NOTE: notification callbacks are not guarenteed to occur within the swing thread.
 */
public interface ProjectViewListener {

	/**
	 * Provides notification that a read-only viewed project has been added which is intended to
	 * be visible.  Notification for hidden viewed projects will not be provided.
	 * @param projectView project view URL
	 */
	void viewedProjectAdded(URL projectView);

	/**
	 * Provides notification that a viewed project is being removed from the project.
	 * Notification for hidden viewed project removal will not be provided.
	 * @param projectView project view URL
	 */
	void viewedProjectRemoved(URL projectView);

}
