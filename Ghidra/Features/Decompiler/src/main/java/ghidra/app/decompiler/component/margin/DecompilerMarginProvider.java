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
package ghidra.app.decompiler.component.margin;

import java.awt.Component;
import java.math.BigInteger;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.LayoutModel;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompilerMarginService;
import ghidra.program.model.listing.Program;

/**
 * A provider of a margin Swing component
 * 
 * <p>
 * To add a margin to the decompiler, a client must implement this interface to provide the
 * component that is actually added to the UI. For a reference implementation, see
 * {@link LineNumberDecompilerMarginProvider}.
 */
public interface DecompilerMarginProvider {

	/**
	 * Called whenever the program, function, or layout changes
	 * 
	 * <p>
	 * The implementation should keep a reference at least to the {@code model} and the
	 * {@code pixmap} for later use during painting. The model provides access to the lines of
	 * decompiler C code. Each layout corresponds to a single line of C code. For example, the first
	 * line of code is rendered by the layout at index 0. The tenth is rendered by the layout at
	 * index 9. Rarely, a line may be wrapped by the renderer, leading to a non-uniform layout. The
	 * {@code pixmap} can map from a pixel's vertical position to the layout index at the same
	 * position in the main panel. It accounts for scrolling an non-uniformity. It is safe to assume
	 * the layouts render contiguous lines of C code. The recommended strategy for painting is thus:
	 * 
	 * <ol>
	 * <li>Compute the visible part of the margin needing repainting. See
	 * {@link JComponent#getVisibleRect()}</li>
	 * <li>Compute the layout indices for the vertical bounds of that part. See
	 * {@link LayoutPixelIndexMap#getIndex(int)}</li>
	 * <li>Iterate over the layouts within those bounds, inclusively.</li>
	 * <li>Compute the vertical position of each layout and paint something appropriate for its
	 * corresponding line. See {@link LayoutPixelIndexMap#getPixel(BigInteger)}</li>
	 * </ol>
	 * 
	 * <p>
	 * A call to this method should cause the component to be repainted.
	 * 
	 * @param program the program for the current function
	 * @param model the line/token model
	 * @param pixmap a map from pixels' y coordinates to layout index, i.e, line number
	 */
	void setProgram(Program program, LayoutModel model, LayoutPixelIndexMap pixmap);

	/**
	 * Get the Swing component implementing the actual margin, often {@code this}
	 * 
	 * @return the component
	 */
	Component getComponent();

	/**
	 * Set the options for the margin
	 * 
	 * <p>
	 * This is called at least once when the provider is added to the margin service. See
	 * {@link DecompilerMarginService#addMarginProvider(DecompilerMarginProvider)}. It subsequently
	 * called whenever a decompiler option changes. To receive other options, the provider will need
	 * to listen using its own mechanism.
	 * 
	 * <p>
	 * A call to this method should cause the component to be repainted. Implementors may choose to
	 * repaint only when certain options change.
	 */
	default void setOptions(DecompileOptions options) {
	}
}
