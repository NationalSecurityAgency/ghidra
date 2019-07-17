/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.util;

import java.io.Serializable;

/**
 * Class to define a selection of GroupPath objects.
 */
public class GroupView implements Serializable {

    private final static long serialVersionUID = 1;
 
    private GroupPath []paths;

    /**
     * Constructor
     * @param paths paths in the view
     */
    public GroupView(GroupPath []paths) {
        this.paths = paths;
    }

    /**
     * Constructor for a single path in the view.
     * @param path the path that is used to create this view.
     */
    public GroupView(GroupPath path) {
        paths = new GroupPath[1];
        paths[0] = path;
    }
    
	/**
	 * Add the given group path to this view.
	 * @param path path to add
	 */
	public void addPath(GroupPath path) {
		GroupPath[] newPaths = new GroupPath[paths.length+1];
		System.arraycopy(paths,0,newPaths,0,paths.length);
		newPaths[paths.length] = path;
		paths = newPaths;
	}

    /**
     * Get the number of paths in the view
     */
    public int getCount() {
        return paths.length;
    }

    /**
     * Get the path at the specified index.
     * @param index the index of the desired path in the view.
     * @throws ArrayIndexOutOfBoundsException if index is invalid.
     */
    public GroupPath getPath(int index) {
        return paths[index];
    }

	/**
	 * Test if the given object is equal to this.
	 */
    @Override
    public boolean equals(Object obj) {

		if (obj == null) {
			return false;
		}
		if (this == obj) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		GroupView gs = (GroupView)obj;

		if (paths.length != gs.paths.length) {
			return false;
		}
		for (int i=0; i<paths.length; i++) {
			if (!paths[i].equals(gs.paths[i])) {
				return false;
			}
		}
		return true;
    }

    /**
     * Return string representation for this object.
     */
    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();
        for (int i=0; i<paths.length; i++) {
            sb.append(paths[i]);
            if (i <paths.length-1) {
                sb.append(", ");
            }
        }
        return sb.toString();
    }
}
