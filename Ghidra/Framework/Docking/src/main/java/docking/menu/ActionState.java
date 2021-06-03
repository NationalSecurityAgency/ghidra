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
package docking.menu;

import javax.swing.Icon;

import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;

/**
 * Note: this class overrides the <code>equals(Object)</code> and relies upon the <code>equals</code>
 * method of the <code>userData</code> object.  Thus, if it is important that equals work for you in 
 * the non-standard identity way, then you must override <code>equals</code> in your user data objects.
 * 
 * @param <T> the type of the action state
 */
public class ActionState<T> {

	private final String name;
	private final Icon icon;
	private T userData;
	private HelpLocation helpLocation;

	public ActionState(String name, Icon icon, T userData) {
		this.name = name;
		this.icon = icon;
		this.userData = userData;
	}

	public String getName() {
		return name;
	}

	public Icon getIcon() {
		return icon;
	}

	public T getUserData() {
		return userData;
	}

	public void setHelpLocation(HelpLocation helpLocation) {
		this.helpLocation = helpLocation;
	}

	public HelpLocation getHelpLocation() {
		return helpLocation;
	}

	@Override
	public boolean equals(Object other) {
		if (other == null) {
			return false;
		}

		Class<? extends Object> otherClass = other.getClass();
		if (!getClass().equals(otherClass)) {
			return false;
		}

		ActionState<?> otherState = (ActionState<?>) other;

		if (!SystemUtilities.isEqual(userData, otherState.userData)) {
			return false;
		}

		return name.equals(otherState.name);
	}

	@Override
	public int hashCode() {
		return name.hashCode() + ((userData == null) ? 0 : userData.hashCode());
	}

	@Override
	public String toString() {
		return name + ": " + userData;
	}
}
