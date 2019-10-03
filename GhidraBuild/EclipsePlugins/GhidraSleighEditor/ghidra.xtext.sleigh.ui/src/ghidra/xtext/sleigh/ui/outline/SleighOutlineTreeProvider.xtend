/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the &quot;License&quot;);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an &quot;AS IS&quot; BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.xtext.sleigh.ui.outline

import java.util.ArrayList
import org.eclipse.emf.ecore.EObject
import org.eclipse.xtext.ui.editor.model.IXtextDocument
import org.eclipse.xtext.ui.editor.outline.IOutlineNode
import org.eclipse.xtext.ui.editor.outline.impl.DefaultOutlineTreeProvider
import org.eclipse.xtext.util.concurrent.IUnitOfWork

/**
 * Customization of the default outline structure.
 *
 * See https://www.eclipse.org/Xtext/documentation/310_eclipse_support.html#outline
 */
class SleighOutlineTreeProvider extends DefaultOutlineTreeProvider {

	// This controls the size of the outline
	//   Displaying the outline can be expensive
	// TODO: figure out performance issue, possibly carefully
	//       building the outline based on Sleigh ideas not pure grammer
	
	override createRoot(IXtextDocument document) {
		if (document.numberOfLines < 100) {
			super.createRoot(document);
		} else {
			new IOutlineNode() {
				
				override getChildren() {
					new ArrayList<IOutlineNode>();
				}
				
				override getFullTextRegion() {
					throw new UnsupportedOperationException("TODO: auto-generated method stub")
				}
				
				override getImage() {
					return null
				}
				
				override getParent() {
					return null
				}
				
				override getSignificantTextRegion() {
					throw new UnsupportedOperationException("TODO: auto-generated method stub")
				}
				
				override getText() {
					return "suppressed outline"
				}
				
				override hasChildren() {
					return false
				}
				
				override <T> getAdapter(Class<T> adapter) {
					throw new UnsupportedOperationException("TODO: auto-generated method stub")
				}
				
				override <Result> readOnly(IUnitOfWork<Result, EObject> work) {
					throw new UnsupportedOperationException("TODO: auto-generated method stub")
				}
				
			}
		}
	}
}
