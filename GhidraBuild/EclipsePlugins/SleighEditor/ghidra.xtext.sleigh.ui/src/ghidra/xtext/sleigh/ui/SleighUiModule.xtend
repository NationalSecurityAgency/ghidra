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
package ghidra.xtext.sleigh.ui

import com.google.inject.Binder
import ghidra.xtext.sleigh.ui.labeling.SleighLabelProvider
import org.eclipse.jface.viewers.ILabelProvider
import org.eclipse.xtend.lib.annotations.FinalFieldsConstructor
import org.eclipse.xtext.ide.editor.syntaxcoloring.ISemanticHighlightingCalculator
import org.eclipse.xtext.ui.editor.contentassist.ContentProposalLabelProvider
import org.eclipse.xtext.ui.editor.hover.IEObjectHoverProvider
import org.eclipse.xtext.ui.editor.model.edit.ITextEditComposer
import org.eclipse.xtext.ui.editor.syntaxcoloring.IHighlightingConfiguration

/**
 * Use this class to register components to be used within the Eclipse IDE.
 */
@FinalFieldsConstructor
class SleighUiModule extends AbstractSleighUiModule {

	override void configureContentProposalLabelProvider(Binder binder) {
		binder.bind(ILabelProvider).annotatedWith(ContentProposalLabelProvider).to(SleighLabelProvider);
	}
	
	def Class<? extends IHighlightingConfiguration> bindIHighlightingConfiguration() {
		return SleighHighlightingConfiguration
	}
	
	def Class<? extends ISemanticHighlightingCalculator> bindISemanticHighlightingCalculator() {
		return SleighHighlightingCalculator
	}
	
	def Class<? extends IEObjectHoverProvider> bindIEObjectHoverProvider() {
		return SleighEObjectHoverProvider
	}

    def Class<? extends ITextEditComposer> bindITextEditComposer() {
        return SleighTextEditComposer
    }
}
