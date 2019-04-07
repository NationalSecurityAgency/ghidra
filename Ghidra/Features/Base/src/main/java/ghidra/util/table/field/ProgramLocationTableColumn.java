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
package ghidra.util.table.field;

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * An table column that knows how to generate ProgramLocation objects for a give row type.
 * @see AbstractProgramBasedDynamicTableColumn
 */
public interface ProgramLocationTableColumn<ROW_TYPE, COLUMN_TYPE> 
        extends ProgramBasedDynamicTableColumn<ROW_TYPE, COLUMN_TYPE> {
    
    /**
     * Determines an appropriate program location associated with this field for the indicated row object.
     * The most probable use is for navigating from the field.
     * @param rowObject the object associated with the table row.
     * @param settings field settings
     * @param program the program associated with the table.
     * @param serviceProvider the plugin tool associated with the table.
     * @return the address associated with the field.
     */
    public ProgramLocation getProgramLocation(ROW_TYPE rowObject, 
            Settings settings, Program program, ServiceProvider serviceProvider);
}
