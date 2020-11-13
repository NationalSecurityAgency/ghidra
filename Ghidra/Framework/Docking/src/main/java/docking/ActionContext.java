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

import docking.action.DockingActionIf;

/**
 * Action context is a class that contains state information that is given to 
 * {@link DockingActionIf}s for them to decide if they are enabled for a given user action.  User
 * actions are toolbar button presses, menu bar item presses and popup menu item presses.   As
 * the user changes focus in the system, all actions are queried with the current context.  Thus,
 * <b>toolbar buttons and menu items will enable and disable as the user interacts with the system.
 * Further, popup menu items will not be added to popup menus when they report false for 
 * {@link DockingActionIf#isAddToPopup(ActionContext)}; they will appear in the popup, but be 
 * disabled if they report <code>true</code> for the above call, but <code>false</code> for 
 * {@link DockingActionIf#isEnabledForContext(ActionContext)}.</b>
 * When the user executes an action, the current context will be passed to the backing 
 * {@link DockingActionIf}.   Ultimately, context serves to control action enablement and to 
 * allow plugins to share state with actions without having to store that state information 
 * in class fields of the plugin.
 * 
 * <p>ComponentProviders are required to return Objects of this type in their getActionContext()
 * methods.  Generally, ComponentProviders have two ways to use this class.  They can either create
 * an ActionContext instance and pass in a contextObject that will be useful to its actions or,
 * subclass the ActionContext object to include specific methods to provide the information that
 * actions will require. 
 * 
 * <p>The data contained by this class has meaning that can change relative to the code that
 * created it.  The intended purpose for the fields of this class is as follows:
 * <ul>
 * 	<li><b>provider</b> - the component provider to which this context belongs; the provider that
 *                        contains the component that is the source of the user action
 *  </li>
 * 	<li><b>contextObject</b> - client-defined data object.  This allows clients to save any 
 *                             information desired to be used when the action is performed.
 *  </li>
 * 	<li><b>sourceObject</b> - when checking enablement, this is the item that was clicked or 
 *                            activated; when performing an action this is either the active
 *                            object or the component that was clicked.  This value may change
 *                            between the check for  
 *                            {@link DockingActionIf#isEnabledForContext(ActionContext) enablement}
 *                            and {@link DockingActionIf#actionPerformed(ActionContext) execution}.
 *  </li>
 *  <li><b>sourceComponent</b> - this value is the component that is the source of the current 
 *                               context.  Whereas the <code>sourceObject</code> is the actual
 *                               clicked item, this value is the focused/active component and 
 *                               will not change between  
 *                               {@link DockingActionIf#isEnabledForContext(ActionContext) enablement}
 *                            	 and {@link DockingActionIf#actionPerformed(ActionContext) execution}.
 *  </li>
 * 	<li><b>mouseEvent</b> - the mouse event that triggered the action; null if the action was
 *                          triggered by a key binding.
 *  </li>
 * </ul>
 * 
 * <p>Ultimately, clients can pass any values they wish for the fields of this class, even if 
 * that changes the meaning of the fields outlined above.
 */

public class ActionContext {
	private ComponentProvider provider;
	private MouseEvent mouseEvent;
	private Object contextObject;
	private Object sourceObject;
	private ActionContext globalContext;

	// Note: the setting of this object is delayed.  This allows clients to build-up the state
	//       of this context.  This object will be set when getSourceComponent() is called if it
	//       has not already been set.
	private Component sourceComponent;

	public ActionContext() {
		this(null, null);
	}

	public ActionContext(ComponentProvider cp) {
		this(cp, null);
	}

	/** 
	 * Basic constructor for ActionContext
	 * @param provider the ComponentProvider that generated this context.
	 * @param sourceComponent an optional source object; this is intended to be the component that
	 *        is the source of the context, usually the focused component
	 */
	public ActionContext(ComponentProvider provider, Component sourceComponent) {
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
	public ActionContext(ComponentProvider provider, Object contextObject,
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

	/**
	 * Returns the {@link ComponentProvider} that generated this ActionContext
	 * @return the provider
	 */
	public ComponentProvider getComponentProvider() {
		return provider;
	}

	/**
	 * Returns the object that was included by the ComponentProvider when this context was created.
	 * @return the object that was included by the ComponentProvider when this context was created.
	 */
	public Object getContextObject() {
		if (contextObject != null) {
			return contextObject;
		}
		return this;
	}

	/**
	 * Sets the context object for this context.  This can be any object of the creator's 
	 * choosing that can be provided for later retrieval.
	 * 
	 * @param contextObject Sets the context object for this context.
	 * @return this context
	 */
	public ActionContext setContextObject(Object contextObject) {
		this.contextObject = contextObject;
		return this;
	}

	/**
	 * Returns the sourceObject from the actionEvent that triggered this context to be generated.
	 * @return the sourceObject from the actionEvent that triggered this context to be generated.
	 */
	public Object getSourceObject() {
		return sourceObject;
	}

	/**
	 * Sets the sourceObject for this ActionContext.  This method is used internally by the 
	 * DockingWindowManager. ComponentProvider and action developers should only use this 
	 * method for testing.
	 * 
	 * @param sourceObject the source object
	 * @return this context
	 */
	public ActionContext setSourceObject(Object sourceObject) {
		this.sourceObject = sourceObject;
		return this;
	}

	/**
	 * Updates the context's mouse event.  Contexts that are based upon key events will have no 
	 * mouse event.   This method is really for the framework to use.  Client calls to this 
	 * method will be overridden by the framework when menu items are clicked.
	 * 
	 * @param e the event that triggered this context.
	 * @return this context
	 */
	public ActionContext setMouseEvent(MouseEvent e) {
		this.mouseEvent = e;
		return this;
	}

	/**
	 * Returns the context's mouse event.  Contexts that are based upon key events will have no 
	 * mouse event.
	 * 
	 * @return the mouse event that triggered this context; null implies a key event-based context
	 */
	public MouseEvent getMouseEvent() {
		return mouseEvent;
	}

	/**
	 * Returns the component that is the target of this context.   This value should not change
	 * whether the context is triggered by a key binding or mouse event.
	 *   
	 * @return the component; may be null
	 */
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

	/**
	 * Returns the global action context for the tool.  The global context is the context of
	 * the default focused component, instead of the normal action context which is the current
	 * focused component.
	 * @return  the global action context for the tool
	 */
	public ActionContext getGlobalContext() {
		if (globalContext == null) {
			Tool tool = getTool();
			globalContext = tool == null ? new ActionContext() : tool.getDefaultToolContext();
		}
		return globalContext;
	}

	private Tool getTool() {
		if (provider != null) {
			return provider.getTool();
		}
		DockingWindowManager manager = DockingWindowManager.getActiveInstance();
		if (manager != null) {
			return manager.getTool();
		}
		return null;
	}

}
