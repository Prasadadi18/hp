import React, { useEffect, useRef } from 'react';

const STAR_COUNT = 200;

export default function StarField() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let animFrame;
    let stars = [];

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };

    const createStars = () => {
      stars = [];
      for (let i = 0; i < STAR_COUNT; i++) {
        stars.push({
          x: Math.random() * window.innerWidth,
          y: Math.random() * window.innerHeight,
          radius: Math.random() * 1.2 + 0.2,
          alpha: Math.random() * 0.6 + 0.1,
          speed: Math.random() * 0.0005 + 0.0002,
          phase: Math.random() * Math.PI * 2,
        });
      }
    };

    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const time = Date.now();

      stars.forEach(star => {
        const twinkle = Math.sin(time * star.speed + star.phase) * 0.3 + 0.7;
        const alpha = star.alpha * twinkle;

        ctx.beginPath();
        ctx.arc(star.x, star.y, star.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(234, 229, 217, ${alpha})`;
        ctx.fill();
      });

      animFrame = requestAnimationFrame(animate);
    };

    resize();
    createStars();
    animate();

    window.addEventListener('resize', resize);
    return () => {
      cancelAnimationFrame(animFrame);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        zIndex: 0,
        pointerEvents: 'none',
      }}
    />
  );
}
