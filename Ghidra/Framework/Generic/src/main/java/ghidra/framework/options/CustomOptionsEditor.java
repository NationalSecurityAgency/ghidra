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
package ghidra.framework.options;

/**
 * Marker interface to signal that the implementing PropertyEditor component desires to handle
 * display editing of an option or options.  This allows options to create custom property
 * editors that can paint and edit a group of interrelated options.
 */
public interface CustomOptionsEditor {
    
    /**
     * Gets the names of the options that this editor is editing. 
     * @return the names of the options that this editor is editing.
     */
    public String[] getOptionNames();
    
    /**
     * Gets the descriptions of the options that this editor is editing.
     * @return the descriptions of the options that this editor is editing.
     */
    public String[] getOptionDescriptions();
}
