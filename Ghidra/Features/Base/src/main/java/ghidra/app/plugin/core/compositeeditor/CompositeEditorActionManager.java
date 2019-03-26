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
package ghidra.app.plugin.core.compositeeditor;

import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.options.Options;
import ghidra.program.model.data.*;

import java.util.*;

import javax.swing.KeyStroke;

import docking.action.KeyBindingData;

/**
 * A CompositeEditorActionManager manages the actions for a single composite editor.
 * By default it provides actions for favorites and cycle groups.
 * Other CompositeEditorActions can be added for it to manage.
 */
public class CompositeEditorActionManager {
	private CompositeEditorProvider provider;
	private ArrayList<CompositeEditorAction> editorActions = new ArrayList<CompositeEditorAction>();
	private ArrayList<CompositeEditorAction> favoritesActions =
		new ArrayList<CompositeEditorAction>();
	private ArrayList<CycleGroupAction> cycleGroupActions = new ArrayList<CycleGroupAction>();

	private ArrayList<EditorActionListener> listeners = new ArrayList<EditorActionListener>();

	private DataTypeManagerService dataTypeMgrService;
	private DataTypeManagerChangeListenerAdapter adapter;

	/**
	 * Constructor
	 * <BR> NOTE: After constructing a manager, you must call setEditorModel() 
	 * and setParentComponent() for the actions to work.
	 * @param plugin the plugin that owns this composite editor action manager
	 * @param program the associated program for obtaining data types.
	 * @param dataTypeMgrService the data type manager service for the
	 * favorites and cycle groups.
	 */
	public CompositeEditorActionManager(CompositeEditorProvider provider) {
		this.provider = provider;
		this.dataTypeMgrService = provider.dtmService;
		adapter = new DataTypeManagerChangeListenerAdapter() {
			@Override
			public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
				setFavoritesActions(dataTypeMgrService.getFavorites());
			}
		};

		List<DataType> favorites = Collections.emptyList();
		if (dataTypeMgrService != null) {
			favorites = dataTypeMgrService.getFavorites();
			dataTypeMgrService.addDataTypeManagerChangeListener(adapter);
		}
		setFavoritesActions(favorites);
		setCycleGroupActions();
	}

	void dispose() {
		if (dataTypeMgrService != null) {
			dataTypeMgrService.removeDataTypeManagerChangeListener(adapter);
		}
		listeners.clear();
		editorActions.clear();
		favoritesActions.clear();
		cycleGroupActions.clear();
		dataTypeMgrService = null;
	}

	/**
	 * Adds a listener that wants notification of actions being added or removed.
	 * @param listener the editor action listener to be notified
	 */
	public void addEditorActionListener(EditorActionListener listener) {
		listeners.add(listener);
	}

	/**
	 * Removes a listener that wanted notification of actions being added or removed.
	 * @param listener the editor action listener that was being notified
	 */
	public void removeEditorActionListener(EditorActionListener listener) {
		listeners.remove(listener);
	}

	/**
	 * Gets the composite editor actions that are currently added to this 
	 * action manager. The favorites and cycle groups actions that the 
	 * manager created by default are not part of the actions returned.
	 * @return the composite editor actions
	 */
	public CompositeEditorAction[] getEditorActions() {
		return editorActions.toArray(new CompositeEditorAction[editorActions.size()]);
	}

	/**
	 * Gets the cycle group actions that the manager created by default.
	 * @return the cycle group actions
	 */
	public CompositeEditorAction[] getFavoritesActions() {
		return favoritesActions.toArray(new CompositeEditorAction[favoritesActions.size()]);
	}

	/**
	 * Gets the favorites actions that the manager created by default.
	 * @return the favorites actions
	 */
	public CompositeEditorAction[] getCycleGroupActions() {
		return cycleGroupActions.toArray(new CompositeEditorAction[cycleGroupActions.size()]);
	}

	/**
	 * Gets all composite editor actions that are currently added to this 
	 * action manager. This includes the favorites and cycle groups actions.
	 * @return all composite editor actions
	 */
	public CompositeEditorAction[] getAllActions() {
		int numActions = getActionCount();
		CompositeEditorAction[] allActions = new CompositeEditorAction[numActions];
		int index = 0;
		int length;
		length = editorActions.size();
		for (int i = 0; i < length; i++, index++) {
			allActions[index] = editorActions.get(i);
		}
		length = favoritesActions.size();
		for (int i = 0; i < length; i++, index++) {
			allActions[index] = favoritesActions.get(i);
		}
		length = cycleGroupActions.size();
		for (int i = 0; i < length; i++, index++) {
			allActions[index] = cycleGroupActions.get(i);
		}
		return allActions;
	}

	/**
	 * Gets the named composite editor action if it exists.
	 * @param actionName the name of the action to find.
	 * @return the action or null
	 */
	public CompositeEditorAction getNamedAction(String actionName) {
		CompositeEditorAction action;
		int length = editorActions.size();
		for (int i = 0; i < length; i++) {
			action = editorActions.get(i);
			if (action.getName().equals(actionName)) {
				return action;
			}
		}
		length = favoritesActions.size();
		for (int i = 0; i < length; i++) {
			action = favoritesActions.get(i);
			if (action.getName().equals(actionName)) {
				return action;
			}
		}
		length = cycleGroupActions.size();
		for (int i = 0; i < length; i++) {
			action = cycleGroupActions.get(i);
			if (action.getName().equals(actionName)) {
				return action;
			}
		}
		return null;
	}

	private int getActionCount() {
		return editorActions.size() + favoritesActions.size() + cycleGroupActions.size();
	}

	/**
	 * Sets the composite editor actions to those in the array.
	 * The manager will still also manage the favorites and cycle group actions.
	 * Any previously set composite editor actions are removed before 
	 * setting the new actions.
	 * @param actions the composite editor actions.
	 */
	public void setEditorActions(CompositeEditorAction[] actions) {
		editorActions.clear();
		for (int i = 0; i < actions.length; i++) {
			editorActions.add(actions[i]);
		}
	}

	private void setFavoritesActions(List<DataType> favorites) {
		clearFavoritesActions();
		for (DataType dataType : favorites) {
			FavoritesAction action = new FavoritesAction(provider, dataType);
			favoritesActions.add(action);
		}
		notifyActionsAdded(favoritesActions);
	}

	private void clearFavoritesActions() {
		notifyActionsRemoved(favoritesActions);
		favoritesActions.clear();
	}

	private void setCycleGroupActions() {
		clearCycleGroupActions();
		for (CycleGroup group : CycleGroup.ALL_CYCLE_GROUPS) {
			CycleGroupAction action = new CycleGroupAction(provider, group);
			cycleGroupActions.add(action);
		}
		notifyActionsAdded(cycleGroupActions);
	}

	private void clearCycleGroupActions() {
		notifyActionsRemoved(cycleGroupActions);
		cycleGroupActions.clear();
	}

	private void notifyActionsAdded(ArrayList<? extends CompositeEditorAction> actions) {
		if (actions.size() <= 0)
			return;
		int length = listeners.size();
		CompositeEditorAction[] cea = actions.toArray(new CompositeEditorAction[actions.size()]);
		for (int i = 0; i < length; i++) {
			listeners.get(i).actionsAdded(cea);
		}
	}

	private void notifyActionsRemoved(ArrayList<? extends CompositeEditorAction> actions) {
		if (actions.size() <= 0)
			return;
		int length = listeners.size();
		CompositeEditorAction[] cea = actions.toArray(new CompositeEditorAction[actions.size()]);
		for (int i = 0; i < length; i++) {
			listeners.get(i).actionsRemoved(cea);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.options.OptionsChangeListener#optionsChanged(ghidra.framework.options.Options, java.lang.String, java.lang.Object, java.lang.Object)
	 */
	public void optionsChanged(Options options, String name, Object oldValue, Object newValue) {
		// Update the editor actions here.
		// The favorites and cycle groups get handled by stateChanged() and cyclegroupChanged().
		CompositeEditorAction[] actions = getEditorActions();
		for (int i = 0; i < actions.length; i++) {
			String actionName = actions[i].getFullName();
			if (actionName.equals(name)) {
				KeyStroke actionKs = actions[i].getKeyBinding();
				KeyStroke oldKs = (KeyStroke) oldValue;
				KeyStroke newKs = (KeyStroke) newValue;
				if (actionKs == oldKs) {
					actions[i].setUnvalidatedKeyBindingData(new KeyBindingData(newKs));
				}
				break;
			}
		}
	}

}
