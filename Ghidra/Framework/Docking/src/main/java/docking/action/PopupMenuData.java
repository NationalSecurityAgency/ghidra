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
package docking.action;

public class PopupMenuData extends MenuData {
	private DockingAction ownerAction;

	/**
	 * Copy constructor.
	 */
	PopupMenuData(DockingAction ownerAction, MenuData menuData) {
		super(menuData);
		this.ownerAction = ownerAction;
	}

	@Override
	protected void firePropertyChanged(MenuData oldData) {
		if (ownerAction != null) {
			ownerAction.firePropertyChanged(DockingActionIf.POPUP_MENU_DATA_PROPERTY, oldData, this);
		}
	}
}
