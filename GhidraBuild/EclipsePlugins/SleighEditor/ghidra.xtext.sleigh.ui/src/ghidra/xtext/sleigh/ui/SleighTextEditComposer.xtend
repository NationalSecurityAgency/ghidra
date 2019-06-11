package ghidra.xtext.sleigh.ui

import org.eclipse.xtext.resource.SaveOptions
import org.eclipse.xtext.ui.editor.model.edit.DefaultTextEditComposer

class SleighTextEditComposer extends DefaultTextEditComposer {
	
	override SaveOptions getSaveOptions() {
		return SaveOptions.newBuilder().format().getOptions();
	}
}