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


public interface StructureEditorModelListener extends CompositeEditorModelListener {

	/**
	 * Called whenever the structure data type editor internal packing state changes
	 * for the data type being edited.
	 * Whether the structure is free form, aligned, or packed to a particular maximum alignment.
	 *
	 * @param type the new packing state: FREE_FORM, ALIGN, PACK, PACK2, PACK4, or PACK8.
	 */
	public abstract void internalAlignmentStateChanged(boolean aligned);

	/**
	 * Called whenever the structure data type editor internal packing state changes
	 * for the data type being edited.
	 * Whether the structure is free form, aligned, or packed to a particular maximum alignment.
	 *
	 * @param type the new packing state: FREE_FORM, ALIGN, PACK, PACK2, PACK4, or PACK8.
	 */
	public abstract void packStateChanged(long packingValue);

}
