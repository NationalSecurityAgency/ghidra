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
package ghidra.program.model.graph;

/**
 *  Handler for selection/location event mappings from/to Ghidra and Renoir.
 */
public interface GraphSelectionHandler {
    /**
     * Check if the graph is the active graph window.
     * 
     * @return true if this handler is active because the window it is handling
     *              is active
     */
    public boolean isActive();
    /**
     * Set the handler to active/inactive based on whether the window it is
     * handling is active or inactive.
     * 
     * @param active true to activate the graph (may pop the graph window to the top)
     */
    public void setActive(boolean active);
    /**
     * Check if the graph is enabled to receive/send events.
     * 
     * @return true if this handler is enabled.  
     */
    public boolean isEnabled();
    /**
     * Set the handler to enabled/disabled.  This sets an enabled flag on
     * this instance and has no affect on the other methods.
     * 
     * @param enabled true to enable mapping selection/location events
     */
    public void setEnabled(boolean enabled);
    /**
     * Translate a Renoir Selection into a Ghidra selection.
     * 
     * @param renoirSelections selection identifiers for selection within Renoir graph
     *                        The Strings are the keys used for the graph vertex
     *                        when generating the graph.
     */
    public void select(String [] renoirSelections);
    /**
     * Translate a Renoir Location into a Ghidra location.
     * 
     * @param renoirLocation string representing the location in renoir
     */
    public void locate(String renoirLocation);
    /**
     * Translate a Ghidra selection into a renoir selection.
     * 
     * @param ghidraSelection ghidra selection object
     * @return set of strings that correspond to a Renoir selection
     *          The strings should be the key strings used when generating the graph.
     */
    public String[] select(Object ghidraSelection);
    /**
     * Translate a Ghidra location into a renoir location.
     * 
     * @param ghidraLocation the location object to translate into a graph key string
     *
     * @return string representation of the location for Renoir.  This should be the
     *                  key of the graph vertex that represents the ghidraLocation object
     *                  on the graph.
     */
    public String locate(Object ghidraLocation);
    
    /**
     * Handle Renoir notification.
     * @param notificationType command from Renoir
     * @return true if notification was handled and there is no need for any other 
     * handler to be notified.
     */
    public boolean notify(String notificationType);
    
    /**
     * Get brief text describing the type of graph.
     *  
     * @return String describing the graph.
     */
    public String getGraphType();
}
