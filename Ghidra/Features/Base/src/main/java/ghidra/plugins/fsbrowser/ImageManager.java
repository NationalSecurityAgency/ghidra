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

import generic.theme.GIcon;

/**
 * Static helper to register and load Icons for the file system browser plugin and its
 * child windows.
 * <p>
 * Visible to just this package.
 */
public class ImageManager {
	//@formatter:off
	public final static Icon COPY = new GIcon("icon.plugin.fsbrowser.copy");
	public final static Icon CUT = new GIcon("icon.plugin.fsbrowser.cut");
	public final static Icon DELETE = new GIcon("icon.plugin.fsbrowser.delete");
	public final static Icon FONT = new GIcon("icon.plugin.fsbrowser.font");
	public final static Icon LOCKED = new GIcon("icon.plugin.fsbrowser.locked");
	public final static Icon NEW = new GIcon("icon.plugin.fsbrowser.new");
	public final static Icon PASTE = new GIcon("icon.plugin.fsbrowser.paste");
	public final static Icon REDO = new GIcon("icon.plugin.fsbrowser.redo");
	public final static Icon RENAME = new GIcon("icon.plugin.fsbrowser.rename");
	public final static Icon REFRESH = new GIcon("icon.plugin.fsbrowser.refresh");
	public final static Icon SAVE = new GIcon("icon.plugin.fsbrowser.save");
	public final static Icon SAVE_AS = new GIcon("icon.plugin.fsbrowser.save.as");
	public final static Icon UNDO = new GIcon("icon.plugin.fsbrowser.undo");
	public final static Icon UNLOCKED = new GIcon("icon.plugin.fsbrowser.unlocked");
	public final static Icon CLOSE = new GIcon("icon.plugin.fsbrowser.close");
	public final static Icon COLLAPSE_ALL = new GIcon("icon.plugin.fsbrowser.collapse.all");
	public final static Icon COMPRESS = new GIcon("icon.plugin.fsbrowser.compress");
	public final static Icon CREATE_FIRMWARE = new GIcon("icon.plugin.fsbrowser.create.firmware");
	public final static Icon EXPAND_ALL = new GIcon("icon.plugin.fsbrowser.expand.all");
	public final static Icon EXTRACT = new GIcon("icon.plugin.fsbrowser.extract");
	public final static Icon INFO = new GIcon("icon.plugin.fsbrowser.info");
	public final static Icon OPEN = new GIcon("icon.plugin.fsbrowser.open");
	public final static Icon OPEN_AS_BINARY = new GIcon("icon.plugin.fsbrowser.open.as.binary");
	public final static Icon OPEN_IN_LISTING = new GIcon("icon.plugin.fsbrowser.open.in.listing");
	public final static Icon OPEN_FILE_SYSTEM = new GIcon("icon.plugin.fsbrowser.open.file.system");
	public final static Icon PHOTO = new GIcon("icon.plugin.fsbrowser.photo");
	public final static Icon VIEW_AS_IMAGE = new GIcon("icon.plugin.fsbrowser.view.as.image");
	public final static Icon VIEW_AS_TEXT = new GIcon("icon.plugin.fsbrowser.view.as.text");
	public final static Icon ECLIPSE = new GIcon("icon.plugin.fsbrowser.eclipse");
	public final static Icon JAR = new GIcon("icon.plugin.fsbrowser.jar");
	public final static Icon IMPORT = new GIcon("icon.plugin.fsbrowser.import");
	public final static Icon iOS = new GIcon("icon.plugin.fsbrowser.ios");
	public final static Icon OPEN_ALL = new GIcon("icon.plugin.fsbrowser.open.all");
	public final static Icon LIST_MOUNTED = new GIcon("icon.plugin.fsbrowser.list.mounted");
	//@formatter:on
}
