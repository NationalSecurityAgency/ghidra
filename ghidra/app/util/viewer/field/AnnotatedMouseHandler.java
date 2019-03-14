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
package ghidra.app.util.viewer.field;

import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.util.ProgramLocation;

import java.awt.event.MouseEvent;

/**
 * An interface for handling mouse clicks on {@link ghidra.util.bean.field.AnnotatedTextFieldElement}s.
 */
public interface AnnotatedMouseHandler {
    
    /**
     * Handles a mouse click for the given program location on an {@link ghidra.util.bean.field.AnnotatedTextFieldElement}.
     * 
     * @param location The program location for the click
     * @param mouseEvent The mouse event that triggered the mouse click
     * @param serviceProvider A service provider used to access system services while processing
     *        the mouse click
     * @return true if the handler wants to be the only handler processing the click.
     */
    public boolean handleMouseClick(ProgramLocation location, MouseEvent mouseEvent, 
        ServiceProvider serviceProvider );
}
