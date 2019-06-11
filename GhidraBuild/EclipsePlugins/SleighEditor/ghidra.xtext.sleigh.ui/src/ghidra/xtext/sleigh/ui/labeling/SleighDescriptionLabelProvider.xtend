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
package ghidra.xtext.sleigh.ui.labeling

import com.google.inject.Inject
import org.eclipse.emf.ecore.EObject
import org.eclipse.emf.ecore.resource.ResourceSet
import org.eclipse.xtext.nodemodel.util.NodeModelUtils
import org.eclipse.xtext.resource.IEObjectDescription
import org.eclipse.xtext.resource.IReferenceDescription
import org.eclipse.xtext.ui.label.DefaultDescriptionLabelProvider
import ghidra.xtext.sleigh.sleigh.exportStmt
import ghidra.xtext.sleigh.sleigh.pequation
import ghidra.xtext.sleigh.sleigh.statement

/**
 * Provides labels for IEObjectDescriptions and IResourceDescriptions.
 * 
 * See https://www.eclipse.org/Xtext/documentation/304_ide_concepts.html#label-provider
 */

/**
 * Provides labels for a IEObjectDescriptions and IResourceDescriptions.
 * 
 * see http://www.eclipse.org/Xtext/documentation.html#labelProvider
 */
class SleighDescriptionLabelProvider extends DefaultDescriptionLabelProvider {
	
	@Inject ResourceSet rdp
	
	// Labels and icons can be computed like this:
	override String getText(Object element) {
		var ele = element;
		
		if (element instanceof IReferenceDescription) {
			var o = rdp.getEObject(element.sourceEObjectUri,true);
			if (o != null){
				return containerLine(o);
			}
			return element.EReference.name
		}
		return super.getText(ele);
	}
	
	def String containerLine(EObject o) {
		var c = o;
		var text = NodeModelUtils.getNode(o).text
		while (c.eContainer != null) {
			if (c instanceof pequation) {
				return NodeModelUtils.getNode(c).text
			}
			if (c instanceof statement ||
				c instanceof exportStmt
			) {
				text = NodeModelUtils.getNode(c).text
				text = text.trim()
				return text				
			}
			c = c.eContainer
		}
		return text
	}
	override text(IEObjectDescription ele) {
		return super.text(ele);
	}
	 
	override image(IEObjectDescription ele) {
		ele.EClass.name + '.gif'
	}	 
}
