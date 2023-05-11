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

import java.io.*;
import java.net.URL;
import java.util.Collection;
import java.util.Set;

import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.protocol.ghidra.GhidraURL;

/**
 * Services that the Tool uses.
 */
public interface ToolServices {

	/** The default tool name for Ghidra  */
	public static final String DEFAULT_TOOLNAME = "DefaultTool";

	/**
	 * Notify the framework that the tool is closing.
	 *
	 * @param tool tool that is closing
	 */
	public void closeTool(PluginTool tool);

	/**
	 * Saves the tool's configuration in the standard
	 * tool location.
	 *
	 * @param tool tool to save.
	 */
	public void saveTool(PluginTool tool);

	/**
	 * Save the tool to the given location on the local file system.
	 *
	 * @param tool the tool template to write
	 * @return the file to which the tool was saved
	 * @throws FileNotFoundException thrown if the file's directory doesn't exist.
	 * @throws IOException thrown if there is an error writing the file.
	 */
	public File exportTool(ToolTemplate tool) throws FileNotFoundException, IOException;

	/**
	 * Get the tool chest for the project
	 * @return the tool chest
	 */
	public ToolChest getToolChest();

	/**
	 * Find a running tool like the one specified that has the named domain file.
	 * If it finds a matching tool, then it is brought to the front.
	 * Otherwise, it creates one and runs it.
	 * It then invokes the specified event on the running tool.
	 *
	 * @param tool find/create a tool like this one.
	 * @param domainFile open this file in the found/created tool.
	 * @param event invoke this event on the found/created tool
	 */
	public void displaySimilarTool(PluginTool tool, DomainFile domainFile, PluginEvent event);

	/**
	 * Returns the default/preferred tool template which should be used to open the specified
	 * domain file, whether defined by the user or the system default.
	 *
	 * @param domainFile The file whose preferred tool should be found.
	 * @return The preferred tool that should be used to open the given file or null if none found.
	 */
	public ToolTemplate getDefaultToolTemplate(DomainFile domainFile);

	/**
	 * Returns the default/preferred tool template which should be used to open the specified
	 * domain file content type, whether defined by the user or the system default.
	 *
	 * @param contentType The content type whose preferred tool should be found.
	 * @return The preferred tool that should be used to open the given file or null if none found.
	 */
	public ToolTemplate getDefaultToolTemplate(String contentType);

	/**
	 * Returns a set of tools that can open the given domain file class.
	 * @param domainClass The domain file class type for which to get tools
	 * @return the tools
	 */
	public Set<ToolTemplate> getCompatibleTools(Class<? extends DomainObject> domainClass);

	/**
	 * Returns the {@link ToolAssociationInfo associations}, which describe content
	 * types and the tools used to open them, for all content types known to the system.
	 *
	 * @return the associations
	 * @see #setContentTypeToolAssociations(Set)
	 */
	public Set<ToolAssociationInfo> getContentTypeToolAssociations();

	/**
	 * Sets the  {@link ToolAssociationInfo associations}, which describe content
	 * types and the tools used to open them, for the system.
	 *
	 * @param infos The associations to be applied
	 * @see #getContentTypeToolAssociations()
	 */
	public void setContentTypeToolAssociations(Set<ToolAssociationInfo> infos);

	/**
	 * Launch the default {@link PluginTool tool} and open the specified domainFiles.
	 * NOTE: running tool reuse is implementation dependent
	 * @param domainFiles the files to open.  A null or empty list will results in an immediate 
	 * return of a null {@link PluginTool}.  Null entries are not permitted.
	 * @return the launched tool.  Null returned if a suitable default tool
	 * for the file content type was not found or failed to launch.
	 */
	public PluginTool launchDefaultTool(Collection<DomainFile> domainFiles);

	/**
	 * Launch the {@link PluginTool tool} with the given name and open the specified domainFiles.
	 * Only those domainFiles with a content type supported by the specified tool will be opened.
	 * NOTE: running tool reuse is implementation dependent.  
	 * @param toolName name of the {@link ToolTemplate tool template} to launch or re-use
	 * @param domainFiles the files to open; may be null or empty.  Null entries are not permitted.
	 * @return the resulting {@link PluginTool tool} or null if the specified tool was not found
	 * or failed to launch
	 */
	public PluginTool launchTool(String toolName, Collection<DomainFile> domainFiles);

	/**
	 * Launch the default tool and open the specified Ghidra URL resource.
	 * The tool chosen will be based upon the content type of the specified resource.
	 * NOTE: running tool re-use is implementation dependent
	 * @param ghidraUrl resource to be opened (see {@link GhidraURL})
	 * @return the launched tool.  Null returned if a failure occurs while accessing the specified
	 * resource or a suitable default tool for the file content type was not found.
	 * @throws IllegalArgumentException if URL protocol is not supported.  Currently, only
	 * the {@code ghidra} protocol is supported.
	 */
	public PluginTool launchDefaultToolWithURL(URL ghidraUrl);

	/**
	 * Launch the tool with the given name and attempt to open the specified Ghidra URL resource.
	 * @param toolName name of the tool to launch
	 * @param ghidraUrl resource to be opened (see {@link GhidraURL})
	 * @return the requested tool or null if the specified tool not found.
	 * @throws IllegalArgumentException if URL protocol is not supported.  Currently, only
	 * the {@code ghidra} protocol is supported.
	 */
	public PluginTool launchToolWithURL(String toolName, URL ghidraUrl);

	/**
	 * Return array of running tools
	 * @return array of Tools
	 */
	public PluginTool[] getRunningTools();

	/**
	 * Returns true if this tool should be saved base on the state of other running instances of
	 * the same tool
	 * @param tool the tool to check for saving
	 * @return true if the tool should be saved
	 */
	public boolean canAutoSave(PluginTool tool);
}
