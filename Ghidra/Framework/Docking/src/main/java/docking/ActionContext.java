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
import java.awt.event.*;

import docking.action.DockingActionIf;

/**
 * ActionContext is an interface used by {@link DockingActionIf}s that contains tool and
 * plugin state information that allows an action to operate. Actions can use the context to get the
 * information it needs to perform its intended purpose. Context is also used to determine if
 * an action should be enabled, should be added to a popup menu, or if it is even valid for the 
 * current context.
 * 
 * <P>
 * The concept of an action being valid or invalid is critical to how the action system works. The
 * reason is that actions can get their context from two different sources. The first
 * source of action context is the current active (focused) {@link ComponentProvider}. This is
 * always the preferred source of context for an action. However, if that context is not valid
 * for an action, the action has the option of specifying that it works on default context. In this
 * case, the tool will use the action's declared context type to see if anyone has registered a
 * default  provider for that type. If so, the action will be given that context 
 * to work on instead of the active context.
 *
 * <P>
 * Whenever the user moves the focus around by clicking on different components or locations in 
 * the tool, all actions are given the opportunity to change their enablement state. The tool 
 * calls each action's {@link DockingActionIf#isEnabledForContext(ActionContext)} method
 * with the new active context (or default context as explained above).  Thus, toolbar 
 * buttons and menu items will enable and disable as the user interacts with the system.
 *
 * <P>
 * When the user executes an action, the current context will be passed to the 
 * {@link DockingActionIf}, again using a possible default context if the active context isn't valid
 * for that action.  Ultimately, context serves to manage actions and to 
 * allow plugins to share state with actions without them being directly coupled together.

 * <P>
 * {@link ComponentProvider}s are required to return ActionContext objects in their 
 * {@link ComponentProvider#getActionContext(MouseEvent)} methods.  Generally, ComponentProviders 
 * have two ways to use this class. They can either create an {@link DefaultActionContext} instance
 * and pass in a contextObject that will be useful to its actions or, subclass the ActionContext
 * object to include specific methods to provide the information that actions will require. If 
 * actions want to work with default context, then they must declare a action context type that is
 * more specific than just ActionContext.
 * 
 * <P>
 * The generic data that all instances of ActionContxt provide is as follows:
 * 
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
 * <P>
 * Typically, component providers will define more specific types of ActionContext where they 
 * can include any additional information that an action might need to work with that component.
 */
public interface ActionContext {

	public ComponentProvider getComponentProvider();

	/**
	 * Returns the object that was included by the ComponentProvider when this context was created.
	 * @return the object that was included by the ComponentProvider when this context was created.
	 */
	public Object getContextObject();

	/**
	 * Sets the context object for this context.  This can be any object of the creator's 
	 * choosing that can be provided for later retrieval.
	 * 
	 * @param contextObject Sets the context object for this context.
	 * @return this context
	 */
	public ActionContext setContextObject(Object contextObject);

	/**
	 * Returns the sourceObject from the actionEvent that triggered this context to be generated.
	 * @return the sourceObject from the actionEvent that triggered this context to be generated.
	 */
	public Object getSourceObject();

	/**
	 * Sets the modifiers for this event that were present when the item was clicked on.
	 * 
	 * @param modifiers bit-masked int, see {@link ActionEvent#getModifiers()} or
	 * {@link MouseEvent#getModifiersEx()}
	 */
	public void setEventClickModifiers(int modifiers);

	/**
	 * Returns the click modifiers for this event.
	 * <p>
	 * Only present for some mouse assisted events, e.g. clicking on a toolbar button or choosing
	 * a menu item in a popup menu. 
	 * 
	 * @return bit-masked int, see {@link InputEvent#SHIFT_MASK}, etc
	 */
	public int getEventClickModifiers();

	/**
	 * Tests the click modifiers for this event to see if they contain any bit from the
	 * specified modifiersMask parameter.
	 * 
	 * @param modifiersMask bitmask to test
	 * @return boolean true if any bit in the eventClickModifiers matches the mask
	 */
	public boolean hasAnyEventClickModifiers(int modifiersMask);

	/**
	 * Sets the sourceObject for this ActionContext.  This method is used internally by the 
	 * DockingWindowManager. ComponentProvider and action developers should only use this 
	 * method for testing.
	 * 
	 * @param sourceObject the source object
	 * @return this context
	 */
	public ActionContext setSourceObject(Object sourceObject);

	/**
	 * Updates the context's mouse event.  Contexts that are based upon key events will have no 
	 * mouse event.   This method is really for the framework to use.  Client calls to this 
	 * method will be overridden by the framework when menu items are clicked.
	 * 
	 * @param e the event that triggered this context.
	 * @return this context
	 */
	public ActionContext setMouseEvent(MouseEvent e);

	/**
	 * Returns the context's mouse event.  Contexts that are based upon key events will have no 
	 * mouse event.
	 * 
	 * @return the mouse event that triggered this context; null implies a key event-based context
	 */
	public MouseEvent getMouseEvent();

	/**
	 * Returns the component that is the target of this context.   This value should not change
	 * whether the context is triggered by a key binding or mouse event.
	 *   
	 * @return the component; may be null
	 */
	public Component getSourceComponent();

}
