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
package docking.options.editor;

import ghidra.framework.options.EditorState;

import java.awt.Dimension;
import java.util.List;

import javax.swing.JPanel;

public abstract class GenericOptionsComponent extends JPanel {
	protected final EditorState editorState;

	/**
	 * Do not use this constructor directly.  Instead, use the factory method:
	 * {@link #createOptionComponent(EditorState)}
	 */
    protected GenericOptionsComponent(EditorState editorState) {
		this.editorState = editorState;
	}

    /**
     * A factory method to create new OptionComponents.
     * @param state The state that will be used to create the correct OptionComponent
     * @return the new OptionComponent.
     */
    public static GenericOptionsComponent createOptionComponent( EditorState state ) {
        if ( state.supportsCustomOptionsEditor() ) {
            return new CustomOptionComponent( state );
        }
        return new DefaultOptionComponent( state );
    }

    /**
     * Creates and sets a preferred alignment based upon the given list of option components.
     * @param components the list of options components from which to determine the alignment.
     */
	public static void alignLabels(List<GenericOptionsComponent> components) {
		int maxWidth = 0;
		int maxHeight = 0;
		for (GenericOptionsComponent optionComponent : components) {
		    Dimension dimension = optionComponent.getPreferredAlignmentSize();
		    maxWidth = Math.max( dimension.width, maxWidth );
		    maxHeight = Math.max( dimension.height, maxHeight );
        }

		for (GenericOptionsComponent component : components) {
		    component.setAlignmentPreferredSize( new Dimension(maxWidth, maxHeight));
        }
	}

	@Override
    public void setEnabled(boolean enabled) {
	}

	/**
	 * Sets the alignment dimension on this component.  This is used internally to align
	 * components.
	 * @param dimension The alignment dimension.
	 */
	protected void setAlignmentPreferredSize( Dimension dimension ) {
	}

	/**
	 * Gets this components alignment dimension.
	 * @return the alignment dimension.
	 */
	protected Dimension getPreferredAlignmentSize() {
	    return getPreferredSize();
	}
}
