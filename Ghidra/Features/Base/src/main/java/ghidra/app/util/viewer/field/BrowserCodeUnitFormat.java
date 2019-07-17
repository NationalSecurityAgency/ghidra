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
package ghidra.app.util.viewer.field;

import javax.swing.event.ChangeListener;

import ghidra.GhidraOptions;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.listing.CodeUnitFormat;

/**
 * <code>BrowserCodeUnitFormat</code> provides a code unit format based upon
 * a common set of viewer Options for specific Tool.  The associated options correspond to
 * the Browser Operand Fields category.
 */
public class BrowserCodeUnitFormat extends CodeUnitFormat {

	/**
	 * Construct code unit format for specified serviceProvider with autoUpdate enabled.
	 * @param serviceProvider service provider (e.g., Tool)
	 */
	public BrowserCodeUnitFormat(ServiceProvider serviceProvider) {
		this(getFieldOptions(serviceProvider), true);
	}

	/**
	 * Construct code unit format for specified serviceProvider.
	 * @param serviceProvider service provider (e.g., Tool)
	 * @param autoUpdate if true format will auto update if associated options are changed.
	 */
	public BrowserCodeUnitFormat(ServiceProvider serviceProvider, boolean autoUpdate) {
		this(getFieldOptions(serviceProvider), autoUpdate);
	}

	/**
	 * Construct code unit format for specified field options.
	 * This constructor must be used by the field factory since an OptionsService may
	 * not obtainable at the time they are constructed.
	 * @param fieldOptions field options
	 * @param autoUpdate if true format will auto update if associated options are changed, in 
	 * addition any listeners will be notified when this format is updated.
	 */
	BrowserCodeUnitFormat(ToolOptions fieldOptions, boolean autoUpdate) {
		super(new BrowserCodeUnitFormatOptions(fieldOptions, autoUpdate));
	}

	private static ToolOptions getFieldOptions(ServiceProvider serviceProvider) {
		OptionsService optionsService = serviceProvider.getService(OptionsService.class);
		if (optionsService == null) {
			throw new IllegalArgumentException("Options service provider not found");
		}
		return optionsService.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
	}

	/**
	 * Add a change listener to the underlying format options.  When a format change
	 * occurs the listener may wish to trigger a refresh of of any formatted code units.
	 * @param listener change listener
	 */
	public void addChangeListener(ChangeListener listener) {
		((BrowserCodeUnitFormatOptions) options).addChangeListener(listener);
	}

	/**
	 * Remove an existing change listener from the underlying format options.
	 * @param listener change listener
	 */
	public void removeChangeListener(ChangeListener listener) {
		((BrowserCodeUnitFormatOptions) options).removeChangeListener(listener);
	}
}
