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
package ghidra.util;

import java.awt.Point;

public class SaveablePoint extends PrivateSaveable {

    private Point point;
    private Class<?>[] fields = new Class<?>[] {
        Double.class, Double.class
    };

    public SaveablePoint() {
        // required for recreating from storage
    }
    
    public SaveablePoint( Point point ) {
        this.point = point;
    }
    
    public Point getPoint() {
        return point;
    }
    
    @Override
	public void restore( ObjectStorage objStorage ) {
        int x = objStorage.getInt();
        int y = objStorage.getInt();
        point = new Point( x, y );
    }

    @Override
	public void save( ObjectStorage objStorage ) {
        objStorage.putInt( (int) point.getX());
        objStorage.putInt( (int) point.getY());
    }
    
    @Override
    public boolean equals( Object obj ) {
        if (obj == this) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass() ) {
            return false;
        }
        return point.equals(((SaveablePoint)obj).point);
    }
    
    @Override
    public int hashCode() {
        return point.hashCode();
    }
    
    @Override
    public String toString() {
        return point.toString();
    }
    
    @Override
	public Class<?>[] getObjectStorageFields() {
        return fields;
    }

    @Override
	public int getSchemaVersion() {
        return 0;
    }

    @Override
	public boolean isUpgradeable( int oldSchemaVersion ) {
        return false;
    }

    @Override
	public boolean upgrade( ObjectStorage oldObjStorage, int oldSchemaVersion,
            ObjectStorage currentObjStorage ) {
        return false;
    }

}
