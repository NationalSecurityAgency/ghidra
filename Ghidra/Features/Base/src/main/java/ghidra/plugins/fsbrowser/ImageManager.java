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

import javax.swing.ImageIcon;

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
	public final static ImageIcon COPY = ResourceManager.loadImage("images/page_copy.png");
	public final static ImageIcon CUT = ResourceManager.loadImage("images/edit-cut.png");
	public final static ImageIcon DELETE = ResourceManager.loadImage("images/page_delete.png");
	public final static ImageIcon FONT = ResourceManager.loadImage("images/text_lowercase.png");
	public final static ImageIcon LOCKED = ResourceManager.loadImage("images/lock.gif");
	public final static ImageIcon NEW = ResourceManager.loadImage("images/page_add.png");
	public final static ImageIcon PASTE = ResourceManager.loadImage("images/page_paste.png");
	public final static ImageIcon REDO = ResourceManager.loadImage("images/redo.png");
	public final static ImageIcon RENAME = ResourceManager.loadImage("images/textfield_rename.png");
	public final static ImageIcon REFRESH = Icons.REFRESH_ICON;
	public final static ImageIcon SAVE = ResourceManager.loadImage("images/disk.png");
	public final static ImageIcon SAVE_AS = ResourceManager.loadImage("images/disk_save_as.png");
	public final static ImageIcon UNDO = ResourceManager.loadImage("images/undo.png");
	public final static ImageIcon UNLOCKED = ResourceManager.loadImage("images/unlock.gif");
	public final static ImageIcon CLOSE = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/door.png");
	public final static ImageIcon COLLAPSE_ALL = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/arrow_in.png");
	public final static ImageIcon COMPRESS = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/compress.png");
	public final static ImageIcon CREATE_FIRMWARE = ResourceManager.loadImage("images/media-flash.png");
	public final static ImageIcon EXPAND_ALL = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/arrow_inout.png");
	public final static ImageIcon EXTRACT = ResourceManager.loadImage("images/package_green.png");
	public final static ImageIcon INFO = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/information.png");
	public final static ImageIcon OPEN = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/door_open.png");
	public final static ImageIcon OPEN_AS_BINARY = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/controller.png");
	public final static ImageIcon OPEN_IN_LISTING = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/folder_table.png");
	public final static ImageIcon OPEN_FILE_SYSTEM = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/folder_brick.png");
	public final static ImageIcon PHOTO = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/photo.png");
	public final static ImageIcon VIEW_AS_IMAGE = ResourceManager.loadImage("images/oxygen/16x16/games-config-background.png");
	public final static ImageIcon VIEW_AS_TEXT = ResourceManager.loadImage("images/format-text-bold.png");
	public final static ImageIcon UNKNOWN = ResourceManager.loadImage("images/help-browser.png");
	public final static ImageIcon IPOD = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/ipod.png");
	public final static ImageIcon IPOD_48 = ResourceManager.loadImage("images/oxygen/48x48/multimedia-player-apple-ipod.png");
	public final static ImageIcon ECLIPSE = ResourceManager.loadImage("images/eclipse.png");
	public final static ImageIcon JAR = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/page_white_cup.png");
	public final static ImageIcon KEY = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/application_key.png");
	public final static ImageIcon IMPORT = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/application_get.png");
	public final static ImageIcon iOS = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/phone.png");
	public final static ImageIcon OPEN_ALL = ResourceManager.loadImage("images/famfamfam_silk_icons_v013/application_cascade.png");
	public final static ImageIcon LIST_MOUNTED = ResourceManager.loadImage("images/downArrow.png");
	//@formatter:on
}
