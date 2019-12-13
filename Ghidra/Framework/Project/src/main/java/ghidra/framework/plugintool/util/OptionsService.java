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
package ghidra.framework.plugintool.util;

import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;

/**
 * Provides a service interface that allows the user to get Options and to check for the 
 * existence of options.
 */
public interface OptionsService {

    /**
     * Get the list of options for all categories.
     * @return the list of options for all categories.
     */
    public Options[] getOptions();
    
    /**
     * Get the options for the given category name.
     * @param category name of category
     * @return the options for the given category name.
     */
    public ToolOptions getOptions(String category);
    
    /**
     * Return whether an Options object exists for the given category.
     * @param category name of the category
     * @return true if an Options object exists
     */
    public boolean hasOptions(String category);
    
    /**
     * Shows Options Dialog with the node denoted by "category" being displayed.  The value is
     * expected to be the name of a node in the options tree, residing under the root node.  You 
     * may also provide the name of such a node, followed by the options delimiter, followed by
     * the name of a child node under that node.  For example, suppose in the options tree exists
     * a node {@literal Root->Foo}  You may pass the value "Foo" to get that node.  Or, suppose
     * in the options tree exists a node {@literal Root->Foo->childNode1}  In this case, you may
     * pass the value "Foo.childNode1", where the '.' character is the delimiter of the 
     * {@link ToolOptions} class (this is the value at the time of writing this documentation).
     * 
     * <p>
     * The filter text parameter is used to set the contents filter text of the options.  You may
     * use this parameter to filter the tree; for example, to show only the node in the tree that
     * you want the user to see.
     *    
     * @param category The category of options to have displayed
     * @param filterText An optional value used to filter the nodes visible in the options tree.
     *                   You may pass <code>null</code> or the empty string <code>""</code> here if you
     *                   do not desire filtering.
     * @throws IllegalArgumentException if the given <code>category</code> value does not exist in
     *                                  the tree of options.
     */
    public void showOptionsDialog(String category, String filterText);

}
