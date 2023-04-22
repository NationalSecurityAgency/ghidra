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
package ghidra.program.model.data;

import java.io.IOException;
import java.io.ObjectInputStream;

import javax.swing.SwingUtilities;

import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 *
 * Default implementation for a {@link DataTypeManagerChangeListener} that sends out the
 * events to its own list of listeners.
 * 
 * NOTE: all listener notifications must be asynchronous within a different thread.
 *  
 */
public class DataTypeManagerChangeListenerHandler implements DataTypeManagerChangeListener {

	private transient WeakSet<DataTypeManagerChangeListener> listenerList =
		WeakDataStructureFactory.createCopyOnReadWeakSet();

	/**
	 * Add the given category change listener.
	 * @param l the listener to be added.
	 */
	public void addDataTypeManagerListener(DataTypeManagerChangeListener l) {
		listenerList.add(l);
	}

	/**
	 * Remove the category change listener.
	 * @param l the listener to be removed.
	 */
	public void removeDataTypeManagerListener(DataTypeManagerChangeListener l) {
		listenerList.remove(l);
	}

	@Override
	public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.categoryAdded(dtm, path);
			}
		});
	}

	@Override
	public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath,
			CategoryPath newPath) {
		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.categoryMoved(dtm, oldPath, newPath);
			}
		});
	}

	@Override
	public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.categoryRemoved(dtm, path);
			}
		});
	}

	@Override
	public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath,
			CategoryPath newPath) {

		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.categoryRenamed(dtm, oldPath, newPath);
			}
		});
	}

	@Override
	public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {

		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.dataTypeAdded(dtm, path);
			}
		});
	}

	@Override
	public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {

		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.dataTypeChanged(dtm, path);
			}
		});
	}

	@Override
	public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath,
			DataTypePath newPath) {

		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.dataTypeMoved(dtm, oldPath, newPath);
			}
		});
	}

	@Override
	public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {

		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.dataTypeRemoved(dtm, path);
			}
		});
	}

	@Override
	public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath,
			DataTypePath newPath) {

		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.dataTypeRenamed(dtm, oldPath, newPath);
				listener.favoritesChanged(dtm, oldPath, false);
			}
		});
	}

	private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException {
		ois.defaultReadObject();
		listenerList = WeakDataStructureFactory.createCopyOnReadWeakSet();
	}

	private void invokeRunnable(Runnable r) {
//		if (SwingUtilities.isEventDispatchThread()) {
//			r.run();
//		}
//		else {
		SwingUtilities.invokeLater(r);
//		}
	}

	@Override
	public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath,
			DataTypePath newPath, DataType newDataType) {

		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.dataTypeReplaced(dtm, oldPath, newPath, newDataType);
			}
		});
	}

	@Override
	public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.favoritesChanged(dtm, path, isFavorite);
			}
		});
	}

	@Override
	public void sourceArchiveChanged(DataTypeManager dataTypeManager,
			SourceArchive dataTypeSource) {

		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.sourceArchiveChanged(dataTypeManager, dataTypeSource);
			}
		});
	}

	@Override
	public void sourceArchiveAdded(DataTypeManager dataTypeManager,
			SourceArchive dataTypeSource) {

		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.sourceArchiveAdded(dataTypeManager, dataTypeSource);
			}
		});
	}

	public void programArchitectureChanged(DataTypeManager dataTypeManager) {
		if (listenerList.isEmpty()) {
			return;
		}
		invokeRunnable(() -> {
			for (DataTypeManagerChangeListener listener : listenerList) {
				listener.programArchitectureChanged(dataTypeManager);
			}
		});
	}
}
