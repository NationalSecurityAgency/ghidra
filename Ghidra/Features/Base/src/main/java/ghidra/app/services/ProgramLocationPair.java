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
package ghidra.app.services;

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/** A simple object that contains a ProgramLocation and its associated Program */
public class ProgramLocationPair {

    private final Program program;
    private final ProgramLocation location;

    public ProgramLocationPair( Program program, ProgramLocation location ) {        
        if ( program == null ) {
            throw new NullPointerException( "Program cannot be null" );
        }
        
        if ( location == null ) {
            throw new NullPointerException( "ProgramLocation cannot be null" );
        }
        
        this.program = program;
        this.location = location;
    }
    
    public Program getProgram() {
        return program;
    }
    
    public ProgramLocation getProgramLocation() {
        return location;
    }
}
