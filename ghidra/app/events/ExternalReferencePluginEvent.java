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
package ghidra.app.events;

import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.symbol.ExternalLocation;

/**
 * Plugin event used to navigate to a location in another program when following
 * a external reference.
 *
 */
public final class ExternalReferencePluginEvent extends PluginEvent { 
	
	/**
	 * The name of this plugin event.
	 */
    public static final String NAME = "ExternalReference";

    private ExternalLocation externalLoc;
	private String programPath;

	/**
	 * Construct a new plugin event.
	 * @param src name of the source of this event
	 * @param extLoc the external location to follow
	 * @param programPath The ghidra path name of the program file to go to.
	 */
    public ExternalReferencePluginEvent(String src,
    				ExternalLocation extLoc, String programPath) {
        super(src,NAME);
     	this.programPath = programPath;
     	externalLoc = extLoc;
    }

    /**
     * Get the external location for this event.
     * @return the external location
     */
    public ExternalLocation getExternalLocation() {
    	return externalLoc;
    }
    
	/**
	 * Returns the program path name
	 * @return String containing the program path name.
	 */
    public String getProgramPath() {
    	return programPath;
    }
}
