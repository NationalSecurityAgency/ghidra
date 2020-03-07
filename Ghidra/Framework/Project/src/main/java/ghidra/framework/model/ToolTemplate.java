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

import javax.swing.ImageIcon;

import org.jdom.Element;

import docking.util.image.ToolIconURL;
import ghidra.framework.plugintool.PluginTool;

/**
 * Configuration of a tool that knows how to create tools.
 */
public interface ToolTemplate {

	String TOOL_XML_NAME = "TOOL";
	String TOOL_NAME_XML_NAME = "TOOL_NAME";
	String TOOL_INSTANCE_NAME_XML_NAME = "INSTANCE_NAME";

	/**
	 * Get the name for the tool.
	 * @return the name
	 */
	String getName();

	/**
	 * Returns the path from whence this tool template came; may be null if the tool was not 
	 * loaded from the filesystem
	 * @return the path
	 */
	String getPath();

	/**
	 * Set the name for the tool template.
	 * 
	 * @param name new tool template name
	 */
	void setName(String name);

	/**
	 * Get the iconURL for this tool template
	 * @return the iconURL for this tool template
	 */
	ToolIconURL getIconURL();

	/**
	 * Get the icon for this tool template.  This is equivalent to calling
	 * <code>getIconURL().getIcon()</code>
	 * @return the icon for this tool template.
	 */
	ImageIcon getIcon();

	/**
	 * Get the classes of the data types that this tool supports,
	 * i.e., what data types can be dropped onto this tool.
	 * @return list of supported data type classes.
	 */
	Class<?>[] getSupportedDataTypes();

	/**
	 * Save this object to an XML Element.
	 * 
	 * @return the ToolConfig saved as an XML element
	 */
	public Element saveToXml();

	/**
	 * Restore this object from a saved XML element.
	 * 
	 * @param root element to restore this object into
	 */
	public void restoreFromXml(Element root);

	/**
	 * Creates a tool like only this template knows how.
	 * @param project the project in which the tool will be living.
	 * @return a new tool for this template implementation.
	 */
	public PluginTool createTool(Project project);

	/**
	 * This returns the XML element that represents the tool part of the overall XML hierarchy.
	 * @return the XML element that represents the tool part of the overall XML hierarchy.
	 */
	public Element getToolElement();
}
