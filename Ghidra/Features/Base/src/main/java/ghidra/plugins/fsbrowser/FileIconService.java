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

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import org.jdom.*;
import org.jdom.input.SAXBuilder;

import generic.jar.ResourceFile;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.ScaledImageIconWrapper;
import resources.icons.TranslateIcon;
import util.CollectionUtils;

/**
 * Provides {@link Icon}s that represent the type and status of a file, based on
 * a filename mapping and caller specified status overlays.
 * <p>
 * The mappings between a file's extension and its icon are stored in a resource
 * file called "file_extension_icons.xml", which is read and parsed the first
 * time this service is referenced.
 * <p>
 * Status overlays are also specified in the file_extension_icons.xml file, and
 * are resized to be 1/2 the width and height of the icon they are being
 * overlayed on.
 * <p>
 * Threadsafe
 * <p>
 */
public class FileIconService {

	private static final class Singleton {
		private static final FileIconService INSTANCE = new FileIconService();
	}

	public static FileIconService getInstance() {
		return Singleton.INSTANCE;
	}

	public static final String OVERLAY_IMPORTED = "imported";
	public static final String OVERLAY_FILESYSTEM = "filesystem";

	private static final String FILEEXT_MAPPING_FILE = "file_extension_icons.xml";
	private static final long DELAY_BETWEEN_TS_CHECKS_MS = 1000 * 10;

	private enum OVERLAYQUAD {
		UL(0, 0), UR(1, 0), LL(0, 1), LR(1, 1);

		OVERLAYQUAD(int x, int y) {
			this.x = x;
			this.y = y;
		}

		int x, y;

		static OVERLAYQUAD fromString(String s, OVERLAYQUAD defaultValue) {
			if (s != null) {
				try {
					return OVERLAYQUAD.valueOf(s.toUpperCase());
				}
				catch (IllegalArgumentException iae) {
					// ignore
				}
			}
			return defaultValue;
		}
	}

	private Map<String, String> fileExtToIconName = new HashMap<>();
	private Map<String, String> fileSubstrToIconName = new HashMap<>();
	private Map<String, String> overlayNameToIconName = new HashMap<>();
	private Map<String, OVERLAYQUAD> overlayNameToQuad = new HashMap<>();
	private String defaultIconPath = "images/famfamfam_silk_icons_v013/page_white.png";
	private int maxExtLevel = 1;
	private boolean debug = false;

	private Map<String, Icon> iconKeyToIcon = new HashMap<>();

	private long lastModifiedTS;
	private long lastCheckedTS;
	private ResourceFile xmlFile;

	private FileIconService() {
		this.xmlFile = Application.findDataFileInAnyModule(FILEEXT_MAPPING_FILE);
		if (xmlFile == null) {
			Msg.error(this, "cannot find file_extension_icons.xml");
		}
	}

	private String makeKey(String key, String[] overlays) {
		StringBuilder sb = new StringBuilder();
		sb.append(key).append("__");
		for (String o : overlays) {
			if (o == null || o.isEmpty()) {
				continue;
			}
			sb.append(o).append("__");
		}
		return sb.toString();
	}

	private Icon getCachedIcon(String key, String path, String... overlays) {
		key = makeKey(key, overlays);
		Icon cachedIcon = iconKeyToIcon.get(key);
		if (cachedIcon == null) {
			cachedIcon = ResourceManager.loadImage(path);
			if (overlays.length > 0) {
				int expectedOW = cachedIcon.getIconWidth() / 2;
				int expectedOH = cachedIcon.getIconHeight() / 2;

				EnumSet<OVERLAYQUAD> usedQuads = EnumSet.noneOf(OVERLAYQUAD.class);
				MultiIcon multiIcon = new MultiIcon(cachedIcon);
				for (String overlay : overlays) {
					if (overlay == null || overlay.isEmpty()) {
						continue;
					}
					String overlayPath = overlayNameToIconName.get(overlay);
					OVERLAYQUAD quad = overlayNameToQuad.get(overlay);
					if (overlayPath == null || quad == null) {
						continue;
					}
					if (usedQuads.contains(quad)) {
						Msg.warn(this, "File icon already contains an overlay at " + quad);
					}
					usedQuads.add(quad);

					ImageIcon overlayIcon = ResourceManager.loadImage(overlayPath);
					if (overlayIcon.getIconHeight() != expectedOH ||
						overlayIcon.getIconWidth() != expectedOW) {
						overlayIcon =
							new ScaledImageIconWrapper(overlayIcon, expectedOW, expectedOH);
					}
					multiIcon.addIcon(
						new TranslateIcon(overlayIcon, quad.x * expectedOW, quad.y * expectedOH));
				}
				cachedIcon = multiIcon;
			}
			iconKeyToIcon.put(key, cachedIcon);
		}
		return cachedIcon;
	}

	/**
	 * Returns an {@link Icon} that represents a file's content based on its
	 * name.
	 *
	 * @param fileName name of file that an icon is being requested for.
	 * @param overlays optional list of overlay names, names of icons that
	 *            should be overlaid on top of the base icon, that represent a
	 *            status or feature independent of the file's base icon.
	 * @return {@link Icon} instance that best represents the named file, never
	 *         null.
	 */
	public synchronized Icon getImage(String fileName, String... overlays) {
		loadIfNeeded();

		fileName = fileName.toLowerCase();
		for (int extLevel = 1; extLevel <= maxExtLevel; extLevel++) {
			String ext = FSUtilities.getExtension(fileName, extLevel);
			if (ext == null) {
				break;
			}
			String path = fileExtToIconName.get(ext);
			if (path != null) {
				return getCachedIcon(ext, path, overlays);
			}
		}

		for (String substr : fileSubstrToIconName.keySet()) {
			if (fileName.indexOf(substr) != -1) {
				return getCachedIcon("####" + substr, fileSubstrToIconName.get(substr), overlays);
			}
		}

		// return default icon for generic file
		return getCachedIcon("", defaultIconPath, overlays);
	}

	/**
	 * Check to see if XML file has changed. If so, then reload the file. This
	 * action will dynamically update the icons without having to restart.
	 */
	protected void loadIfNeeded() {
		long now = System.currentTimeMillis();
		if (now - lastCheckedTS > DELAY_BETWEEN_TS_CHECKS_MS) {
			lastCheckedTS = now;
			if (debug || xmlFile.lastModified() != lastModifiedTS) {
				lastModifiedTS = xmlFile.lastModified();
				load();
			}
		}
	}

	private void load() {
		fileExtToIconName.clear();
		fileSubstrToIconName.clear();
		overlayNameToIconName.clear();
		overlayNameToQuad.clear();
		iconKeyToIcon.clear();
		defaultIconPath = null;
		maxExtLevel = 1;

		try (InputStream xmlInputStream = xmlFile.getInputStream()) {
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
			Document doc = sax.build(xmlInputStream);
			Element root = doc.getRootElement();
			for (Element child : CollectionUtils.asList(root.getChildren("file_extension"),
				Element.class)) {
				String extension = child.getAttributeValue("extension");
				String iconPath = child.getAttributeValue("icon");
				if (extension.endsWith(".")) {
					addSubstrMapping(extension, iconPath);
				}
				else if (!extension.isEmpty()) {
					addExtMapping(extension, iconPath);
				}
				else {
					defaultIconPath = iconPath;
				}
			}
			for (Element child : CollectionUtils.asList(root.getChildren("file_overlay"),
				Element.class)) {
				String name = child.getAttributeValue("name");
				String iconPath = child.getAttributeValue("icon");
				OVERLAYQUAD quadrant =
					OVERLAYQUAD.fromString(child.getAttributeValue("quadrant"), OVERLAYQUAD.LR);

				overlayNameToIconName.put(name, iconPath);
				overlayNameToQuad.put(name, quadrant);
			}
		}
		catch (JDOMException | IOException e) {
			Msg.showError(this, null, "Error reading file icon data", e.getMessage(), e);
		}
	}

	private void addSubstrMapping(String substr, String iconPath) {
		fileSubstrToIconName.put(substr, iconPath);
	}

	private void addExtMapping(String ext, String iconPath) {
		fileExtToIconName.put(ext, iconPath);
		maxExtLevel = Math.max(maxExtLevel, countExtLevel(ext));
	}

	private int countExtLevel(String ext) {
		int count = 0;
		for (int i = 0; i < ext.length(); i++) {
			if (ext.charAt(i) == '.') {
				count++;
			}
		}
		return count;
	}

}
