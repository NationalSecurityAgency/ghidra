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

import java.awt.event.MouseEvent;

/**
 * ComponentProviders are required to return Objects of this type in their getActionContext()
 * methods.  Generally, ComponentProviders have two ways to use this class.  They can either create
 * an ActionContext instance and pass in a contextObject that will be useful to its actions or,
 * subclass the ActionContext object to include specific methods to provide the information that
 * actions will require. 
 */

public class ActionContext {
	private ComponentProvider provider;
	private Object contextObject;
	private Object sourceObject;
	private MouseEvent mouseEvent;

	public ActionContext() {
		this(null, null);
	}

	/** 
	 * Basic constructor for ActionContext
	 * @param provider the ComponentProvider that generated this context.
	 * @param contextObject an optional contextObject that the ComponentProvider can provide
	 * to the action. 
	 */
	public ActionContext(ComponentProvider provider, Object contextObject) {
		this.provider = provider;
		this.contextObject = contextObject;
	}

	/**
	 * Constructor
	 * 
	 * @param provider the ComponentProvider that generated this context.
	 * @param contextObject an optional contextObject that the ComponentProvider can provide
	 * @param sourceObject an optional source object; this can be anything that actions wish to
	 *        later retrieve
	 */
	public ActionContext(ComponentProvider provider, Object contextObject, Object sourceObject) {
		this(provider, contextObject);
		this.sourceObject = sourceObject;
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
	 */
	public void setContextObject(Object contextObject) {
		this.contextObject = contextObject;
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
	 * DockingWindowManager. ComponentProvider and action developers should
	 * only use this method for testing.
	 * @param sourceObject
	 */
	public void setSource(Object sourceObject) {
		this.sourceObject = sourceObject;
	}

	/**
	 * Updates the context's mouse event.  Contexts that are based upon key events will have no 
	 * mouse event.
	 * 
	 * @param e the event that triggered this context.
	 */
	public void setMouseEvent(MouseEvent e) {
		this.mouseEvent = e;
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
}
