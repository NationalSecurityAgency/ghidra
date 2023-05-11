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
package docking;

import java.awt.Component;
import java.awt.event.MouseEvent;

/**
 * The default implementation of ActionContext
 */
public class DefaultActionContext implements ActionContext {
	private ComponentProvider provider;
	private MouseEvent mouseEvent;
	private Object contextObject;
	private Object sourceObject;
	private int eventClickModifiers;

	// Note: the setting of this object is delayed.  This allows clients to build-up the state
	//       of this context.  This object will be set when getSourceComponent() is called if it
	//       has not already been set.
	private Component sourceComponent;

	/**
	 * Default constructor with no provider, context object, or source component
	 */
	public DefaultActionContext() {
		this(null, null);
	}

	/** 
	 * Constructor with no source component and no context object
	 * @param provider the ComponentProvider that generated this context.
	 */
	public DefaultActionContext(ComponentProvider provider) {
		this(provider, null);
	}

	/** 
	 * Constructor for ActionContext with context object and sourceComponent being the same
	 * @param provider the ComponentProvider that generated this context.
	 * @param sourceComponent an optional source object; this is intended to be the component that
	 *        is the source of the context, usually the focused component
	 */
	public DefaultActionContext(ComponentProvider provider, Component sourceComponent) {
		this(provider, sourceComponent, sourceComponent);
	}

	/**
	 * Constructor
	 * 
	 * @param provider the ComponentProvider that generated this context.
	 * @param contextObject an optional contextObject that the ComponentProvider can provide; this 
	 *        can be anything that actions wish to later retrieve
	 * @param sourceComponent an optional source object; this is intended to be the component that
	 *        is the source of the context, usually the focused component
	 */
	public DefaultActionContext(ComponentProvider provider, Object contextObject,
			Component sourceComponent) {
		this.provider = provider;
		this.contextObject = contextObject;
		this.sourceObject = sourceComponent;
		this.sourceComponent = sourceComponent;
	}

	private void lazyDeriveSourceComponent() {

		if (sourceComponent != null) {
			// Do not allow this to change once set.  This prevents the value from getting changed
			// when the user clicks a menu item.
			return;
		}

		// check this in order of preference
		if (sourceObject instanceof Component) {
			sourceComponent = (Component) sourceObject;
			return;
		}

		if (mouseEvent != null) {
			sourceComponent = mouseEvent.getComponent();
			return;
		}

		if (contextObject instanceof Component) {
			sourceComponent = (Component) contextObject;
		}
	}

	@Override
	public ComponentProvider getComponentProvider() {
		return provider;
	}

	@Override
	public Object getContextObject() {
		if (contextObject != null) {
			return contextObject;
		}
		return this;
	}

	@Override
	public DefaultActionContext setContextObject(Object contextObject) {
		this.contextObject = contextObject;
		return this;
	}

	@Override
	public Object getSourceObject() {
		return sourceObject;
	}

	@Override
	public void setEventClickModifiers(int modifiers) {
		this.eventClickModifiers = modifiers;
	}

	@Override
	public int getEventClickModifiers() {
		return eventClickModifiers;
	}

	@Override
	public boolean hasAnyEventClickModifiers(int modifiersMask) {
		return (eventClickModifiers & modifiersMask) != 0;
	}

	@Override
	public DefaultActionContext setSourceObject(Object sourceObject) {
		this.sourceObject = sourceObject;
		return this;
	}

	@Override
	public DefaultActionContext setMouseEvent(MouseEvent e) {
		if (e != null) {
			this.mouseEvent = e;
			this.eventClickModifiers = e.getModifiersEx();
		}
		return this;
	}

	@Override
	public MouseEvent getMouseEvent() {
		return mouseEvent;
	}

	@Override
	public Component getSourceComponent() {
		lazyDeriveSourceComponent();
		return sourceComponent;
	}

	@Override
	public String toString() {

		//@formatter:off
		return "{\n" +
			"\tprovider: " + provider + ",\n" + 
			"\tcontextObject: " + contextObject + ",\n" +
			"\tsourceObject: " + sourceObject + ",\n" +
			"\tsourceComponent: " + sourceComponent + ",\n" +
			"\tmouseEvent: " + mouseEvent + "\n" +
		"}";
		//@formatter:on
	}
}
