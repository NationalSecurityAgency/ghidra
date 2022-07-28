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
package docking.theme.laf;

import java.awt.Color;
import java.awt.Component;
import java.util.List;

import javax.swing.*;

import docking.theme.*;
import ghidra.docking.util.LookAndFeelUtils;

public class WrappingLookAndFeel extends LookAndFeel {
	private LookAndFeel delegate;

	WrappingLookAndFeel(LookAndFeel delegate) {
		this.delegate = delegate;
	}

	@Override
	public UIDefaults getDefaults() {
		GThemeValueMap javaDefaults = new GThemeValueMap();

		UIDefaults defaults = delegate.getDefaults();
		List<String> colorIds = LookAndFeelUtils.getLookAndFeelIdsForType(defaults, Color.class);
		for (String id : colorIds) {
			Color color = defaults.getColor(id);
			ColorValue value = new ColorValue(id, color);
			javaDefaults.addColor(value);
		}
		Gui.setJavaDefaults(javaDefaults);
		for (String id : colorIds) {
			defaults.put(id, Gui.getGColorUiResource(id));
//			defaults.put(id, new GColor(id));
		}
		defaults.put("Label.textForeground", Gui.getGColorUiResource("Label.foreground"));
		GColor.refreshAll();
		GIcon.refreshAll();
		return defaults;
	}

	@Override
	public String getName() {
		return delegate.getName();
	}

	@Override
	public String getID() {
		return delegate.getID();
	}

	@Override
	public String getDescription() {
		return delegate.getDescription();
	}

	@Override
	public boolean isNativeLookAndFeel() {
		return delegate.isNativeLookAndFeel();
	}

	@Override
	public boolean isSupportedLookAndFeel() {
		return delegate.isSupportedLookAndFeel();
	}

	@Override
	public LayoutStyle getLayoutStyle() {
		return delegate.getLayoutStyle();
	}

	@Override
	public void provideErrorFeedback(Component component) {
		delegate.provideErrorFeedback(component);
	}

	@Override
	public Icon getDisabledIcon(JComponent component, Icon icon) {
		return delegate.getDisabledIcon(component, icon);
	}

	@Override
	public Icon getDisabledSelectedIcon(JComponent component, Icon icon) {
		return delegate.getDisabledSelectedIcon(component, icon);
	}

	@Override
	public boolean getSupportsWindowDecorations() {
		return delegate.getSupportsWindowDecorations();
	}

	@Override
	public void initialize() {
		delegate.initialize();
	}

	@Override
	public void uninitialize() {
		delegate.uninitialize();
	}

	@Override
	public String toString() {
		return "Wrapped: " + delegate.toString();
	}
}
