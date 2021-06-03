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
package ghidra.framework.project.tool;

import java.util.ArrayList;

import javax.swing.ImageIcon;

import org.jdom.Element;

import docking.util.image.ToolIconURL;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

/**
 * Implementation for a tool template that has the class names of the
 * plugins that are part of the tool, and the tool's icon.
 */
public class GhidraToolTemplate implements ToolTemplate {
	private static final String CLASS_NAME_XML_NAME = "CLASS_NAME";
	private static final String LOCATION_XML_NAME = "LOCATION";
	private static final String ICON_XML_NAME = "ICON";
	public static String TEMPLATE_NAME = "Ghidra_Tool_Template";
	private Class<?>[] supportedDataTypes;

	private Element toolElement;
	private ToolIconURL iconURL;

	/** The place from whence this tool came*/
	private String path;

	/**
	 * Constructor.
	 * @param root XML element that contains the tool template data
	 * @param path the path of the template
	 */
	public GhidraToolTemplate(Element root, String path) {
		this.path = path;
		restoreFromXml(root);
	}

	public GhidraToolTemplate(ToolIconURL iconURL, Element toolElement,
			Class<?>[] supportedDataTypes) {
		this.iconURL = iconURL;
		this.toolElement = toolElement;
		this.supportedDataTypes = supportedDataTypes;
	}

	@Override
	public String getName() {
		return toolElement.getAttributeValue(TOOL_NAME_XML_NAME);
	}

	@Override
	public String getPath() {
		return path;
	}

	@Override
	public void setName(String name) {
		toolElement.setAttribute(TOOL_NAME_XML_NAME, name);
	}

	@Override
	public ImageIcon getIcon() {
		return iconURL.getIcon();
	}

	@Override
	public Class<?>[] getSupportedDataTypes() {
		return supportedDataTypes;
	}

	/**
	 * Get the icon URL.
	 */
	@Override
	public ToolIconURL getIconURL() {
		return iconURL;
	}

	/**
	 * Returns a hash code value for the object. This method is
	 * supported for the benefit of hashtables such as those provided by
	 * <code>java.util.Hashtable</code>.
	 */
	@Override
	public int hashCode() {
		return getName().hashCode();
	}

	/**
	 * Indicates whether some other object is "equal to" this one.
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		GhidraToolTemplate otherTemplate = (GhidraToolTemplate) obj;
		if (hashCode() != otherTemplate.hashCode()) {
			return false;
		}

		return getName().equals(otherTemplate.getName());
	}

	/**
	 * Returns a string representation of the object. In general, the
	 * <code>toString</code> method returns a string that
	 * "textually represents" this object. The result should
	 * be a concise but informative representation that is easy for a
	 * person to read.
	 */
	@Override
	public String toString() {
		return getName() + " - " + path;
	}

	@Override
	public void restoreFromXml(Element root) {
		java.util.List<?> list = root.getChildren("SUPPORTED_DATA_TYPE");
		java.util.List<Class<?>> dtList = new ArrayList<>();
		for (int i = 0; i < list.size(); ++i) {
			Element elem = (Element) list.get(i);
			String className = elem.getAttribute(CLASS_NAME_XML_NAME).getValue();
			try {
				dtList.add(Class.forName(className));
			}
			catch (ClassNotFoundException e) {
				Msg.error(this, "Class not found: " + className, e);
			}
			catch (Exception exc) {//TODO
				Msg.error(this, "Unexpected Exception: " + exc.getMessage(), exc);
			}
		}
		supportedDataTypes = new Class<?>[dtList.size()];
		dtList.toArray(supportedDataTypes);

		Element iconElem = root.getChild(ICON_XML_NAME);

		String location = iconElem.getAttributeValue(LOCATION_XML_NAME);
		String iconText = iconElem.getText();

		if (iconText != null && iconText.length() > 0) {
			iconText = iconText.trim();
			byte[] imageBytes = NumericUtilities.convertStringToBytes(iconText);
			iconURL = new ToolIconURL(location, imageBytes);
		}
		else {
			iconURL = new ToolIconURL(location);
		}

		toolElement = root.getChild(TOOL_XML_NAME);
	}

	@Override
	public Element saveToXml() {
		Element root = new Element("TOOL_CONFIG");
		root.setAttribute("CONFIG_NAME", "NO_LONGER_USED");	// only here so 4.3 doesn't blow up after
															// opening a project in 4.4
		for (Class<?> supportedDataType : supportedDataTypes) {
			Element elem = new Element("SUPPORTED_DATA_TYPE");
			elem.setAttribute(CLASS_NAME_XML_NAME, supportedDataType.getName());
			root.addContent(elem);
		}

		Element iconElem = new Element(ICON_XML_NAME);
		iconElem.setAttribute(LOCATION_XML_NAME, iconURL.getLocation());
		if (iconURL.getIconBytes() != null) {
			iconElem.setText(NumericUtilities.convertBytesToString(iconURL.getIconBytes()));
		}
		root.addContent(iconElem);

		root.addContent((Element) (toolElement.clone()));

		return root;
	}

	public void setIconURL(ToolIconURL url) {
		iconURL = url;
	}

	@Override
	public Element getToolElement() {
		return toolElement;
	}

	@Override
	public PluginTool createTool(Project project) {
		return new GhidraTool(project, this);
	}
}
