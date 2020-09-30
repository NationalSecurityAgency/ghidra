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
package ghidra.graph.visualization;

import java.awt.geom.Point2D;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.interpolation.PropertySetter;
import org.jungrapht.visualization.MultiLayerTransformer;
import org.jungrapht.visualization.VisualizationViewer;

import ghidra.graph.job.AbstractAnimatorJob;

public class CenterAnimationJob extends AbstractAnimatorJob {
	protected int duration = 1000;
	private final Point2D oldPoint;
	private final Point2D newPoint;
	private final Point2D lastPoint = new Point2D.Double();
	private final VisualizationViewer<?, ?> viewer;

	public CenterAnimationJob(VisualizationViewer<?, ?> viewer,
			Point2D oldPoint, Point2D newPoint) {
		this.viewer = viewer;
		this.oldPoint = oldPoint;
		this.newPoint = newPoint;
		lastPoint.setLocation(oldPoint.getX(), oldPoint.getY());
	}

	@Override
	public Animator createAnimator() {
		Animator newAnimator =
			PropertySetter.createAnimator(duration, this, "percentComplete", 0.0, 1.0);
		newAnimator.setAcceleration(0f);
		newAnimator.setDeceleration(0.8f);

		return newAnimator;
	}

	public void setPercentComplete(double percentComplete) {

		double journeyX = (newPoint.getX() - oldPoint.getX()) * percentComplete;
		double journeyY = (newPoint.getY() - oldPoint.getY()) * percentComplete;

		double newX = oldPoint.getX() + journeyX;
		double newY = oldPoint.getY() + journeyY;

		double deltaX = lastPoint.getX() - newX;
		double deltaY = lastPoint.getY() - newY;

		lastPoint.setLocation(newX, newY);
		if (deltaX == 0 && deltaY == 0) {
			return;
		}

		viewer.getRenderContext()
				.getMultiLayerTransformer()
				.getTransformer(MultiLayerTransformer.Layer.LAYOUT)
				.translate(deltaX, deltaY);
		viewer.repaint();
	}

	@Override
	public void finished() {
		setPercentComplete(1);
	}

}

