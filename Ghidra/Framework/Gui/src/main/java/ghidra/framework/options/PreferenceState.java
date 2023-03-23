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

import org.jdom.Element;

/**
 * An implementation of SaveState that exists primarily to signal its intended usage.  The 
 * SaveState is a generic object for saving program state through plugins.  This state object
 * is meant to be used for preferences <b>that are not associated directly with a plugin</b>.
 */
public class PreferenceState extends SaveState {
    public static final String PREFERENCE_STATE_NAME = "PREFERENCE_STATE";
    
    public PreferenceState() {
        super( PREFERENCE_STATE_NAME );
    }
    
    /**
     * Initializes a new state object from the given element.
     * @param element The element from which to initialize.
     */
    public PreferenceState( Element element ) {
        super( element );   
    }    
}
