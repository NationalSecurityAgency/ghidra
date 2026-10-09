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
package ghidra.app.plugin.core.bento;

import java.awt.*;
import java.util.List;

import generic.theme.GThemeDefaults.Colors;

public class BentoBox {

	protected final String id;
	protected final List<BoundedObject> obj;

	protected Color color;

	public BentoBox(String id, BoundedObject objX, BoundedObject objY, Color color) {
		this.id = id;
		this.obj = List.of(objX, objY);
		this.color = color;
	}

	public BentoBox(String id, List<BoundedObject> objects, Color color) {
		this.id = id;
		this.color = color;
		this.obj = List.copyOf(objects);
	}

	public String getId() {
		return id;
	}

	public int getNumIndices() {
		return obj.size();
	}

	public long getLowBound(int index) {
		return obj.get(index).loBound;
	}

	public long getHighBound(int index) {
		return obj.get(index).hiBound;
	}

	public Color getColor() {
		return color;
	}

	public void setColor(Color color) {
		this.color = color;
	}

	public BoundedObject getObj(int index) {
		return obj.get(index);
	}

	public MappedObject getMappedObj(int index) {
		return obj.get(index).getMappedObject();
	}

	public int getPixelStart(int index) {
		return getMappedObj(index).getPixelStart();
	}

	public int getPixelWidth(int index) {
		return getMappedObj(index).getPixelWidth();
	}

	public void render(Graphics g, int xIndex, int yIndex) {
		int x = getPixelStart(xIndex);
		int w = getPixelWidth(xIndex);
		int y = getPixelStart(yIndex);
		int h = getPixelWidth(yIndex);
		g.setColor(Colors.BORDER);
		g.fillRect(x - 1, y - 1, w + 2, h + 2);
		g.setColor(color);
		g.fillRect(x, y, w, h);
	}

	public Rectangle getRectangle(int xIndex, int yIndex) {
		BoundedObject objX = obj.get(xIndex);
		BoundedObject objY = obj.get(yIndex);
		return new Rectangle(
			(int) objX.getStart(), (int) objY.getStart(),
			(int) (objX.getStop() - objX.getStart() + 1),
			(int) (objY.getStop() - objY.getStart() + 1));
	}

	@Override
	public String toString() {
		return id != null ? id : "BentoBox (unnamed)";
	}

}
