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
package ghidra.app.plugin.core.symboltree;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.RenderingHints;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.font.FontRenderContext;
import java.awt.font.TextLayout;
import java.awt.geom.AffineTransform;
import java.awt.geom.Area;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

public class InfiniteProgressPanel extends JComponent implements MouseListener {

    private static final String DEFAULT_MESSAGE_TEXT = "";
    private static final int DEFAULT_NUMBER_OF_BARS = 14;
    private static final float DEFAULT_SHIELD = .60F;
    private static final int DEFAULT_FRAMES_PER_SECOND = 7;
    private static final int DEFAULT_FADEIN_DELAY = 300;
    
    protected String text = DEFAULT_MESSAGE_TEXT;
    protected int fadeDelay = DEFAULT_FADEIN_DELAY;
    protected float shield = DEFAULT_SHIELD;    
    protected int barsCount = DEFAULT_NUMBER_OF_BARS;
    protected int fps = DEFAULT_FRAMES_PER_SECOND;
    protected RenderingHints hints;
    protected Area[] ticker;
    
    // state values    
    protected Thread animation;
    protected boolean paintAnimation = false;
    protected int alphaLevel = 0;
    
    public InfiniteProgressPanel() {
        this( DEFAULT_MESSAGE_TEXT );
    }
    
    public InfiniteProgressPanel( String text ) {
        this( text, DEFAULT_NUMBER_OF_BARS );
    }
    
    public InfiniteProgressPanel( String text, int barsCount ) {
        this( text, barsCount, DEFAULT_SHIELD );
    }
    
    public InfiniteProgressPanel( String text, int barsCount, float shield ) {
        this( text, barsCount, shield, DEFAULT_FRAMES_PER_SECOND );
    }
    
    public InfiniteProgressPanel( String text, int barsCount, float shield, int fps ) {
        this( text, barsCount, shield, fps, DEFAULT_FADEIN_DELAY );
    }
    
    public InfiniteProgressPanel( String text, int barsCount, float shield, int fps, int rampDelay ) {
        setText( text );
        this.fadeDelay = rampDelay >= 0 ? rampDelay : 0;
        this.shield = shield >= 0.0f ? shield : 0.0f;
        this.fps = fps > 0 ? fps : 15;
        this.barsCount = barsCount > 0 ? barsCount : 14;
        
        this.hints = new RenderingHints( RenderingHints.KEY_RENDERING,
            RenderingHints.VALUE_RENDER_QUALITY );
        this.hints.put( RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON );
        this.hints.put( RenderingHints.KEY_FRACTIONALMETRICS,
            RenderingHints.VALUE_FRACTIONALMETRICS_ON );        
    }
    
    public void setText( String newText ) {
        text = newText;
        if ( text == null ) {
            text = "";
        }
        repaint();
    }
    
    public String getText() {
        return text;
    }
    
    public void start() {      
        if ( animation != null ) {
            animation.interrupt();
        }
        
        removeMouseListener( this ); // be sure not to add the listener twice
        addMouseListener( this );
        setVisible( true );
        
        ticker = buildTicker( barsCount );
        double fixIncrement = 2.0 * Math.PI / (barsCount);      
        animation = new Thread( new Animator( fixIncrement, fadeDelay ) );
        animation.start();        
    }
    
    public void stop() {
        if ( animation != null ) {
            animation.interrupt();
            animation = null;
            double fixIncrement = 2.0 * Math.PI / (barsCount);
            animation = new Thread( new FadeOutAnimator( fixIncrement, fadeDelay) );
            animation.start();
        }
    }
    
    public void interrupt() {
        if ( animation != null ) {
            animation.interrupt();
            animation = null;
            removeMouseListener(this);
            setVisible(false);
        }
    }
    
    private Area[] buildTicker( int barCount ) {
        Area[] newTicker = new Area[barCount];
        Point2D.Double center = new Point2D.Double( (double) getWidth() / 2,
            (double) getHeight() / 2 );        
        double fixedAngle = 2.0 * Math.PI / (barCount);
        for ( double i = 0.0; i < barCount; i++ ) {
            Area primitive = buildPrimitive();
            AffineTransform toCenter = AffineTransform.getTranslateInstance(center.getX(), 
                center.getY() );
            AffineTransform toBorder = AffineTransform.getTranslateInstance(45.0, -6.0 );
            AffineTransform toCircle = AffineTransform.getRotateInstance(-i * fixedAngle,
                center.getX(), center.getY() );
            
            AffineTransform toWheel = new AffineTransform();
            toWheel.concatenate(toCenter);
            toWheel.concatenate(toBorder);
            
            primitive.transform(toWheel);
            primitive.transform(toCircle);
            
            newTicker[(int) i] = primitive;
        }
        
        return newTicker;
    }
    
    private Area buildPrimitive() {
        Rectangle2D.Double body = new Rectangle2D.Double( 6, 0, 30, 12 ); // location and size
        Ellipse2D.Double head = new Ellipse2D.Double( 0, 0, 12, 12 );
        Ellipse2D.Double tail = new Ellipse2D.Double( 30, 0, 12, 12 );
        
        Area tick = new Area(body);
        tick.add( new Area( head ) );
        tick.add( new Area( tail ) );
        
        return tick;
    }

    @Override
    public void paintComponent( Graphics g ) {
        if ( !paintAnimation ) {            
            return;
        }
        
        int width = getWidth();
        int height = getHeight();       
        double maxY = 0.0;          
        Graphics2D g2 = (Graphics2D) g;
        g2.setRenderingHints(hints);

        g2.setColor( new Color( 255, 255, 255, (int) (alphaLevel * shield) ) );
        g2.fillRect(0, 0, width, height);

double textPosition = 0.0;
for ( Area element : ticker ) {
    Rectangle2D bounds = element.getBounds2D();
    if ( bounds.getMaxY() > textPosition ) {
        textPosition = bounds.getMaxY();
    }
}        
        
        int channel = 0;
        int blue = 255;
        Color textColor = Color.BLACK;
        for ( int i = 0; i < ticker.length; i++ ) {
            
            
            channel = 264 - 128 / (i + 1);               
            blue = channel+126 > 255 ? 255 : channel+126;
            Color color = new Color( channel, channel, blue, (int) (alphaLevel * shield) );

            if ( i == 0 ) {
                textColor = color; 
            }
            
            g2.setColor( color );
            g2.fill( ticker[i] );

            Rectangle2D bounds = ticker[i].getBounds2D();
            if ( bounds.getMaxY() > maxY ) {
                maxY = bounds.getMaxY();
            }            
        }
paintText( g2, textColor, textPosition );        
    }

private void paintText( Graphics2D graphics, Color color, double textPosition ) { 
    if ( text == null || text.trim().length() == 0 ) {
        return;
    }
    
    FontRenderContext context = graphics.getFontRenderContext();
    TextLayout layout = new TextLayout( text, getFont(), context );
    Rectangle2D bounds = layout.getBounds();
    graphics.setColor( Color.BLACK );
    layout.draw( graphics, (float) (getWidth() - bounds.getWidth()) / 2,
        (float) (textPosition + layout.getLeading() + 2 * layout.getAscent() ) );
}    
    
    // fade out
    private class FadeOutAnimator implements Runnable {
        
        private final int fadeDelayTime;
        private AffineTransform transformToCircle;
        private long startRampupTime;
        
        private FadeOutAnimator( double transformTheta, int fadeDelayTime ) {
            this.fadeDelayTime = fadeDelayTime;
            
            Point2D.Double center = new Point2D.Double( (double) getWidth() / 2, 
                (double) getHeight() / 2 );      
            transformToCircle = AffineTransform.getRotateInstance(transformTheta, 
                center.getX(), center.getY() );
        }
        
        public void run() {            
            startRampupTime = System.currentTimeMillis();
            if ( fadeDelayTime == 0 ) {
                alphaLevel = 0;
            }
            
            while ( !Thread.interrupted() && (alphaLevel > 0) ) {                
                transformTicker();
                
                repaint();
                
                updateBackgroundAlpha();
                
                if ( !pauseForEffect() ) {
                    break;
                }
            }
            
            paintAnimation = false;
            repaint();
            
            setVisible(false);
            removeMouseListener( InfiniteProgressPanel.this );            
        }        

        // true indicates a successful pause
        protected boolean pauseForEffect() {
            try {
                Thread.sleep( (1000/fps) );
            } catch ( InterruptedException ie ) {
                return false; // we've stopped the thread
            }
            Thread.yield();
            return true;
        }

        protected void transformTicker() {
            for ( Area element : ticker ) {                      
                element.transform( transformToCircle );
            }
        }
        
        protected void updateBackgroundAlpha() {
            if ( alphaLevel <= 0 ) {
                return;
            }

            int elapsedTime = (int) (System.currentTimeMillis() - startRampupTime);
            int increment = (255 * elapsedTime) / fadeDelayTime;
            alphaLevel = 255 - increment;
            if ( alphaLevel <= 0 ) {
                alphaLevel = 0;
            }
        }
    }
        
    private class Animator implements Runnable {
        
        private boolean inRampUpPeriod = false;
        private final int rampDelayTime;
        private AffineTransform transformToCircle;
        private long startRampupTime;
        
        protected Animator( double transformTheta, int rampDelayTime ) {
            this.rampDelayTime = rampDelayTime;
            
            Point2D.Double center = new Point2D.Double( (double) getWidth() / 2, 
                (double) getHeight() / 2 );      
            transformToCircle = AffineTransform.getRotateInstance(transformTheta, 
                center.getX(), center.getY() );
        }
        
        public void run() {
            startRampupTime = System.currentTimeMillis();
            if ( rampDelayTime == 0 ) {
                alphaLevel = 255;             
            }
            
            paintAnimation = true;
            inRampUpPeriod = true;
            
            while ( !Thread.interrupted() ) {
                transformTicker();
          
                repaint();
                
                updateBackgroundAlpha();
                
                if ( !pauseForEffect() ) {
                    break;
                }
            }
        }
        
        // true indicates a successful pause
        protected boolean pauseForEffect() {
            try {
                Thread.sleep( (1000/fps) );
            } catch ( InterruptedException ie ) {
                return false; // we've stopped the thread
            }
            Thread.yield();
            return true;
        }
        
        protected void transformTicker() {
            if ( inRampUpPeriod ) {                
                return;
            }
            
            for ( Area element : ticker ) {                      
                element.transform( transformToCircle );
            }
        }
        
        protected void updateBackgroundAlpha() {
            if ( alphaLevel >= 255 ) {
                inRampUpPeriod = false;                
                return;
            }
            
            int elapsedTime = (int) (System.currentTimeMillis() - startRampupTime);
            int increment = (255 * elapsedTime) / rampDelayTime;
            alphaLevel = increment;
            if ( alphaLevel >= 255 ) {
                alphaLevel = 255;
                inRampUpPeriod = false;
            }
        }
    }
    
    public void mouseClicked(MouseEvent e) {
        Toolkit.getDefaultToolkit().beep();
    }

    public void mouseEntered(MouseEvent e) {
    }

    public void mouseExited(MouseEvent e) {
    }

    public void mousePressed(MouseEvent e) {
    }

    public void mouseReleased(MouseEvent e) {
    }
    
    
    
    public static void main( String[] args ) {
        
        
        final JFrame frame = new JFrame( "Ticker Test" );
        frame.setSize( 400, 600 );
        final Component originalGlassPane = frame.getGlassPane();
        final InfiniteProgressPanel progressPanel = new InfiniteProgressPanel("Processing request...");
    progressPanel.fps = 7;
        progressPanel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked( MouseEvent e ) {                
                //progressPanel.interrupt();
                progressPanel.stop();
                frame.setGlassPane(originalGlassPane);
            }
        } );
        
        
        JPanel mainPanel = new JPanel( new BorderLayout() );
        
        JScrollPane scrollPane = new JScrollPane();
        final JTextArea textArea = new JTextArea( 50, 40 );
        textArea.setText("some text here..." );
        scrollPane.getViewport().add( textArea );
        mainPanel.add( scrollPane, BorderLayout.CENTER );
        
        JButton button = new JButton( "Start" );
        button.addActionListener(new ActionListener() {
            
            public void actionPerformed( ActionEvent event ) {
                frame.setGlassPane(progressPanel);                    
                progressPanel.start();
            }
        } );
        mainPanel.add( button, BorderLayout.SOUTH );
                
        frame.setSize( 400, 400 );
        frame.setLocation( GraphicsEnvironment.getLocalGraphicsEnvironment().getCenterPoint() );
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        frame.getContentPane().add( mainPanel );
        frame.setVisible( true );
    }
}
