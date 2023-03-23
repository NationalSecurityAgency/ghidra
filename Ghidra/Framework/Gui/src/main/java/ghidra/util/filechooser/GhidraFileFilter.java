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
package ghidra.util.filechooser;

import java.io.File;

/**
 * A interface that filters out all files 
 * except for those type extensions that it knows about.
 * Extensions are of the type ".foo", which is typically found on
 * Windows and Unix boxes, but not on Macinthosh. Case is ignored.
 */
public interface GhidraFileFilter {
    /**
     * A default implementation that shows all files.
     */
    public final static GhidraFileFilter ALL = new GhidraFileFilter() {
        public String getDescription() {
            return "All Files (*.*)";
        }
        public boolean accept(File pathname, GhidraFileChooserModel model) {
            return true;
        }
    };

    /**
     * Tests whether or not the specified abstract pathname should be
     * included in a pathname list.
     *
     * @param  pathname  The abstract pathname to be tested
     * @param  model     The underlying file chooser model
     * 
     * @return  <code>true</code> if and only if <code>pathname</code>
     *          should be included
     */
    boolean accept(File pathname, GhidraFileChooserModel model);

    /**
     * Returns the description of this filter.
     * @return the description of this filter
     */
    public String getDescription();
}
