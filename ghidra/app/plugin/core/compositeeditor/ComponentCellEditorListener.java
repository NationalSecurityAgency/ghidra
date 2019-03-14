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
package ghidra.app.plugin.core.compositeeditor;

/**
 * The composite data type editor uses this listener so that the cell editor can indicate
 * to the panel that it should try to stop editing the current cell and move to the indicated cell.
 */
interface ComponentCellEditorListener {
    static int NEXT = 1;
    static int PREVIOUS = 2;
    static int UP = 3;
    static int DOWN = 4;
    
    void moveCellEditor(int direction, String value);
    
}
