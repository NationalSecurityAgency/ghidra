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
package ghidra.app.util;

import java.util.ArrayList;
import java.util.List;

import docking.DialogComponentProvider;

/**
 * Dialog for editing the import options for a selected importer format.
 */
public class OptionsDialog extends DialogComponentProvider implements OptionListener {

	private OptionsEditorPanel optionRenderer;
	private List<Option> options = new ArrayList<>();
	private boolean cancelled = false;
	private OptionValidator validator;

	/**
	 * Contructs a new OptionsDialog for editing the options associated with a specific import format
	 * such as PE, ELF, XML, etc.
	 *
	 * @param originalOptions the list of options generated from the specific import format selected.
	 * @param validator a callback for validating the options as they are set.
	 * @param addressFactoryService a service for retrieving the AddressFactory if needed. This is
	 * passed instead of an actual AddressFactory, because to get an AddressFactory, it might
	 * require that a language be loaded or a program be opened and not all options require an
	 * AddressFactory.
	 */
	public OptionsDialog(List<Option> originalOptions,
			OptionValidator validator, AddressFactoryService addressFactoryService) {
		super("Options");

		this.validator = validator;

		// Make a copy of the options to avoid changing the original ones in case the dialog
		// cancelled.  Also us as a listener to each option so that we will be notified and
		// can validate and update various fields.
		for (Option originalOption : originalOptions) {
			Option option = originalOption.copy();
			option.setOptionListener(this);
			options.add(option);
		}

		optionRenderer = new OptionsEditorPanel(options, addressFactoryService);

		addOKButton();
		addCancelButton();
		addWorkPanel(optionRenderer);
		setRememberSize(false);
	}

	@Override
	public void optionChanged(Option option) {
		String message = validator.validateOptions(options);
		if (message != null) {
			setStatusText(message);
			setOkEnabled(false);
		}
		else {
			setStatusText("");
			setOkEnabled(true);
		}
	}

	@Override
	protected void okCallback() {
		close();
	}

	@Override
	protected void cancelCallback() {
		cancelled = true;
		super.cancelCallback();
	}

	public boolean wasCancelled() {
		return cancelled;
	}

	@Override
	public void close() {
		super.close();

		// clear out the listener for the options
		for (Option option : options) {
			option.setOptionListener(null);
		}
	}

	/**
	 * Returns the list of Options with the values as they were set in this dialog.
	 * @return the list of Options with the values as they were set in this dialog.
	 */
	public List<Option> getOptions() {
		return options;
	}

}
