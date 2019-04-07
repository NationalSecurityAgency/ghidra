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
package ghidra.framework.model;

/**
 * Interface to define methods to manage tools in a central location. 
 */
public interface ToolChest {
                               
    
    /**
     * Get the tool template for the given tool name.
     * @param toolName name of tool
     * @return null if there is no tool template for the given
     * toolName.
     */
    public ToolTemplate getToolTemplate(String toolName);

    /**
     * Get the tool templates from the tool chest.
     * @return list of tool template
     */
    public ToolTemplate[] getToolTemplates();

    /**
     * Add a listener to be notified when the tool chest is changed.
     * @param l listener to add
     */
    public void addToolChestChangeListener(ToolChestChangeListener l);

    /**
     * 
     * Remove a listener that is listening to when the tool chest is changed.
     * @param l to remove
     */
    public void removeToolChestChangeListener(ToolChestChangeListener l);

    /**
     * Add tool template to the tool chest.
     * <br>
     * Note: If the given tool template name already exists in the project, then the name will 
     * be altered by appending an underscore and a one-up value.  The <code>template</code>
     * parameter's name is also updated with then new name. 
     * <p>
     * To simply replace a tool with without changing its name, call 
     * {@link #replaceToolTemplate(ToolTemplate)}
     * 
     * @param template tool template to add
     */
    public boolean addToolTemplate(ToolTemplate template);

    /**
     * Remove entry (toolTemplate or toolSet) from the tool chest.
     * 
     * @param toolName name of toolConfig or toolSet to remove
     * @return true if the toolConfig or toolset was
     * successfully removed from the tool chest.
     */
    public boolean remove(String toolName);
    
    /**
     * Get the number of tools in this tool chest.
     * @return tool count.
     */
    public int getToolCount();

    /**
     * Performs the same action as calling {@link #remove(String)} and then 
     * {@link #addToolTemplate(ToolTemplate)}.  However, calling this method prevents state from 
     * being lost in the transition, such as position in the tool chest and default tool status.
     * 
     * @param template The template to add to the tool chest, replacing any tools with the same name.
     * @return True if the template was added.
     */
    public boolean replaceToolTemplate(ToolTemplate template);
}
