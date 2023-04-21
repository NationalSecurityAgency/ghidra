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

import java.awt.FontMetrics;

import javax.swing.Icon;

import docking.widgets.fieldpanel.field.SimpleImageField;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.viewer.proxy.EmptyProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;

/**
 * Class for displaying images in fields.
 */
public class ImageFactoryField extends SimpleImageField implements ListingField {

	private FieldFactory factory;
	private ProxyObj<?> proxy;

	/**
	 * Constructor
	 * @param factory the FieldFactory that generated this field.
	 * @param icon the ImageIcon to display.
	 * @param proxy the object that this field represents.
	 * @param metrics the FontMetrics used to render.
	 * @param x the starting x position for this field.
	 * @param width the width of this field.
	 */
	public ImageFactoryField(FieldFactory factory,
			Icon icon,
			ProxyObj<?> proxy,
			FontMetrics metrics,
			int x,
			int width) {
		this(factory, icon, proxy, metrics, x, width, false);
	}

	/**
	 * Constructor
	 * @param factory the FieldFactory that generated this field.
	 * @param icon the ImageIcon to display.
	 * @param proxy the object that this field represents.
	 * @param metrics the FontMetrics used to render.
	 * @param x the starting x position for this field.
	 * @param width the width of this field.
	 * @param center centers the image if true.
	 */
	public ImageFactoryField(FieldFactory factory,
			Icon icon,
			ProxyObj<?> proxy,
			FontMetrics metrics,
			int x,
			int width,
			boolean center) {

		super(icon, metrics, x, 0, width, center);
		this.factory = factory;
		this.proxy = proxy;
	}

	@Override
	public FieldFactory getFieldFactory() {
		return factory;
	}

	@Override
	public ProxyObj<?> getProxy() {
		if (proxy == null) {
			return EmptyProxy.EMPTY_PROXY;
		}
		return proxy;
	}

	@Override
	public Object getClickedObject(FieldLocation fieldLocation) {
		return this;
	}
}
