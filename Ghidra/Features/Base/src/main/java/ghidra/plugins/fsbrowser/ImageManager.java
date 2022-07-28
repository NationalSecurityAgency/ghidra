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
package ghidra.plugins.fsbrowser;

import javax.swing.Icon;

import resources.Icons;
import resources.ResourceManager;

/**
 * Static helper to register and load Icons for the file system browser plugin and its
 * child windows.
 * <p>
 * Visible to just this package.
 */
public class ImageManager {
	//@formatter:off
	public final static Icon COPY = ResourceManager.loadImage("images/page_copy.png");
	public final static Icon CUT = ResourceManager.loadImage("images/edit-cut.png");
	public final static Icon DELETE = ResourceManager.loadImage("images/page_delete.png");
	public final static Icon FONT = ResourceManager.loadImage("images/text_lowercase.png");
	public final static Icon LOCKED = ResourceManager.loadImage("images/lock.gif");
	public final static Icon NEW = ResourceManager.loadImage("images/page_add.png");
	public final static Icon PASTE = ResourceManager.loadImage("images/page_paste.png");
	public final static Icon REDO = ResourceManager.loadImage("images/redo.png");
	public final static Icon RENAME = ResourceManager.loadImage("images/textfield_rename.png");
	public final static Icon REFRESH = Icons.REFRESH_ICON;
	public final static Icon SAVE = ResourceManager.loadImage("images/disk.png");
	public final static Icon SAVE_AS = ResourceManager.loadImage("images/disk_save_as.png");
	public final static Icon UNDO = ResourceManager.loadImage("images/undo.png");
	public final static Icon UNLOCKED = ResourceManager.loadImage("images/unlock.gif");
	public final static Icon CLOSE = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/door.png");
	public final static Icon COLLAPSE_ALL = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/arrow_in.png");
	public final static Icon COMPRESS = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/compress.png");
	public final static Icon CREATE_FIRMWARE = ResourceManager.loadImage("images/media-flash.png");
	public final static Icon EXPAND_ALL = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/arrow_inout.png");
	public final static Icon EXTRACT = ResourceManager.loadImage("images/package_green.png");
	public final static Icon INFO = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/information.png");
	public final static Icon OPEN = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/door_open.png");
	public final static Icon OPEN_AS_BINARY = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/controller.png");
	public final static Icon OPEN_IN_LISTING = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/folder_table.png");
	public final static Icon OPEN_FILE_SYSTEM = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/folder_brick.png");
	public final static Icon PHOTO = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/photo.png");
	public final static Icon VIEW_AS_IMAGE = ResourceManager.loadImage("images/oxygen/16x16/games-config-background.png");
	public final static Icon VIEW_AS_TEXT = ResourceManager.loadImage("images/format-text-bold.png");
	public final static Icon UNKNOWN = ResourceManager.loadImage("images/help-browser.png");
	public final static Icon IPOD = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/ipod.png");
	public final static Icon IPOD_48 = ResourceManager.loadImage("images/oxygen/48x48/multimedia-player-apple-ipod.png");
	public final static Icon ECLIPSE = ResourceManager.loadImage("images/eclipse.png");
	public final static Icon JAR = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/page_white_cup.png");
	public final static Icon KEY = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/application_key.png");
	public final static Icon IMPORT = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/application_get.png");
	public final static Icon iOS = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/phone.png");
	public final static Icon OPEN_ALL = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/application_cascade.png");
	public final static Icon LIST_MOUNTED = ResourceManager.loadImage("images/downArrow.png");
	//@formatter:on
}
