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
package ghidra.feature.vt.gui.provider.markuptable;

import javax.swing.Icon;

import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.TranslateIcon;

public class MarkupStatusIcons {
	public static final Icon APPLIED_ICON = ResourceManager.loadImage("images/checkmark_green.gif");
	public static final Icon APPLY_ADD_MENU_ICON =
		ResourceManager.loadImage("images/Plus.png");
	public static final Icon APPLY_REPLACE_MENU_ICON =
		ResourceManager.loadImage("images/sync_enabled.png");
	private static final Icon SCALED_ADD_ICON =
		ResourceManager.getScaledIcon(APPLY_ADD_MENU_ICON, 12, 12);
	private static final Icon SCALED_REPLACE_ICON =
		ResourceManager.getScaledIcon(APPLY_REPLACE_MENU_ICON, 12, 12);
	private static final Icon ADDED_ICON = new TranslateIcon(SCALED_ADD_ICON, 14, 4);
	private static final Icon REPLACED_ICON = new TranslateIcon(SCALED_REPLACE_ICON, 14, 4);
	private static final Icon SHIFTED_APPLIED = new TranslateIcon(APPLIED_ICON, 8, 0);
	public static final Icon APPLIED_ADDED_ICON = new MultiIcon(APPLIED_ICON, ADDED_ICON);
	public static final Icon APPLIED_REPLACED_ICON = new MultiIcon(APPLIED_ICON, REPLACED_ICON);

	public static final Icon REJECTED_ICON = ResourceManager.loadImage("images/dialog-cancel.png");
	public static final Icon DONT_CARE_ICON =
		ResourceManager.loadImage("images/asterisk_orange.png");
	public static final Icon DONT_KNOW_ICON = ResourceManager.loadImage("images/unknown.gif");
	public static final Icon FAILED_ICON = ResourceManager.loadImage("images/edit-delete.png");
	public static final Icon SAME_ICON = new MultiIcon(APPLIED_ICON, SHIFTED_APPLIED);
	public static final Icon CONFLICT_ICON = ResourceManager.loadImage("images/cache.png");
}
