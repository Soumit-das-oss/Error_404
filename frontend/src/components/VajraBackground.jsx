import { useEffect, useRef } from 'react';

export default function VajraBackground() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    let animationFrameId;
    let bolts = [];
    let flashAlpha = 0;
    let nextStrikeTime = performance.now() + (Math.random() * 5000 + 7000);

    const resizeCanvas = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();

    class Bolt {
      constructor(x, y) {
        this.segments = [{ x, y }];
        this.life = 1.0; 
        this.branches = [];
        this.generateSegments();
      }

      generateSegments() {
        let currentX = this.segments[0].x;
        let currentY = this.segments[0].y;
        
        while (currentY < canvas.height) {
          const dx = (Math.random() - 0.5) * 80;
          const dy = Math.random() * 40 + 10;
          
          currentX += dx;
          currentY += dy;
          
          this.segments.push({ x: currentX, y: currentY });
          
          // Generate branches
          if (Math.random() < 0.3) {
            let bX = currentX;
            let bY = currentY;
            const branchSegments = [{ x: bX, y: bY }];
            const branchLength = Math.floor(Math.random() * 5) + 3;
            
            for (let i = 0; i < branchLength; i++) {
              bX += (Math.random() - 0.5) * 60;
              bY += Math.random() * 30;
              branchSegments.push({ x: bX, y: bY });
            }
            this.branches.push(branchSegments);
          }
        }
      }

      draw(ctx) {
        if (this.life <= 0) return;

        // Aura/Glow (Electric Amber)
        ctx.beginPath();
        ctx.moveTo(this.segments[0].x, this.segments[0].y);
        for (let i = 1; i < this.segments.length; i++) {
          ctx.lineTo(this.segments[i].x, this.segments[i].y);
        }
        ctx.strokeStyle = `rgba(245, 158, 11, ${0.4 * this.life})`;
        ctx.lineWidth = 4;
        ctx.shadowBlur = 15;
        ctx.shadowColor = '#F59E0B';
        ctx.stroke();

        // Core (White-gold)
        ctx.beginPath();
        ctx.moveTo(this.segments[0].x, this.segments[0].y);
        for (let i = 1; i < this.segments.length; i++) {
          ctx.lineTo(this.segments[i].x, this.segments[i].y);
        }
        ctx.strokeStyle = `rgba(254, 240, 138, ${this.life})`;
        ctx.lineWidth = 1;
        ctx.shadowBlur = 0;
        ctx.stroke();

        // Draw Branches
        this.branches.forEach(branch => {
          ctx.beginPath();
          ctx.moveTo(branch[0].x, branch[0].y);
          for (let i = 1; i < branch.length; i++) {
            ctx.lineTo(branch[i].x, branch[i].y);
          }
          ctx.strokeStyle = `rgba(245, 158, 11, ${0.3 * this.life})`;
          ctx.lineWidth = 2;
          ctx.stroke();
          
          ctx.beginPath();
          ctx.moveTo(branch[0].x, branch[0].y);
          for (let i = 1; i < branch.length; i++) {
            ctx.lineTo(branch[i].x, branch[i].y);
          }
          ctx.strokeStyle = `rgba(254, 240, 138, ${0.8 * this.life})`;
          ctx.lineWidth = 1;
          ctx.stroke();
        });
      }
    }

    const render = (time) => {
      // Clear with pure void black
      ctx.fillStyle = '#050507';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Trigger lightning strike based on low-frequency timer
      if (time > nextStrikeTime) {
        const startX = Math.random() * canvas.width;
        bolts.push(new Bolt(startX, 0));
        flashAlpha = 0.08; 
        nextStrikeTime = time + (Math.random() * 5000 + 7000); // 7 to 12 seconds
      }

      // Draw ambient lightning flash in the atmosphere
      if (flashAlpha > 0) {
        ctx.fillStyle = `rgba(245, 158, 11, ${flashAlpha})`;
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        flashAlpha -= 0.005; // Fade out quickly
      }

      for (let i = bolts.length - 1; i >= 0; i--) {
        bolts[i].draw(ctx);
        bolts[i].life -= 0.03; 
        if (bolts[i].life <= 0) {
          bolts.splice(i, 1);
        }
      }

      animationFrameId = window.requestAnimationFrame(render);
    };
    
    animationFrameId = window.requestAnimationFrame(render);

    return () => {
      window.removeEventListener('resize', resizeCanvas);
      window.cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas 
      ref={canvasRef} 
      className="fixed inset-0 pointer-events-none z-0"
      style={{ background: '#050507' }}
    />
  );
}
