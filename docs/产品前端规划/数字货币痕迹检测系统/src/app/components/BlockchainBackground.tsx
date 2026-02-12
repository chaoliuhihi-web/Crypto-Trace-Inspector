import { useEffect, useRef } from "react";

interface Node {
  x: number;
  y: number;
  vx: number;
  vy: number;
  connections: number[];
  pulsePhase: number;
  isBlock: boolean;
}

interface DataPacket {
  from: number;
  to: number;
  progress: number;
  speed: number;
}

export function BlockchainBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const nodesRef = useRef<Node[]>([]);
  const packetsRef = useRef<DataPacket[]>([]);
  const animationRef = useRef<number>();
  const timeRef = useRef(0);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    // 设置画布尺寸
    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener("resize", resize);

    // 初始化节点
    const nodeCount = 35;
    nodesRef.current = Array.from({ length: nodeCount }, (_, i) => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      connections: [],
      pulsePhase: Math.random() * Math.PI * 2,
      isBlock: Math.random() > 0.8, // 20% 是区块节点
    }));

    // 绘制网格背景
    const drawGrid = () => {
      ctx.strokeStyle = "rgba(58, 63, 74, 0.15)";
      ctx.lineWidth = 1;

      const gridSize = 60;
      const offsetX = (timeRef.current * 0.05) % gridSize;
      const offsetY = (timeRef.current * 0.05) % gridSize;

      // 垂直线
      for (let x = -offsetX; x < canvas.width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }

      // 水平线
      for (let y = -offsetY; y < canvas.height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }
    };

    // 绘制扫描线效果
    const drawScanLine = () => {
      const scanY = (timeRef.current * 2) % canvas.height;
      const gradient = ctx.createLinearGradient(0, scanY - 40, 0, scanY + 40);
      gradient.addColorStop(0, "rgba(79, 195, 247, 0)");
      gradient.addColorStop(0.5, "rgba(79, 195, 247, 0.08)");
      gradient.addColorStop(1, "rgba(79, 195, 247, 0)");

      ctx.fillStyle = gradient;
      ctx.fillRect(0, scanY - 40, canvas.width, 80);
    };

    // 更新节点位置
    const updateNodes = () => {
      nodesRef.current.forEach((node) => {
        node.x += node.vx;
        node.y += node.vy;

        // 边界反弹
        if (node.x < 0 || node.x > canvas.width) node.vx *= -1;
        if (node.y < 0 || node.y > canvas.height) node.vy *= -1;

        // 限制在画布内
        node.x = Math.max(0, Math.min(canvas.width, node.x));
        node.y = Math.max(0, Math.min(canvas.height, node.y));

        node.pulsePhase += 0.03;
      });
    };

    // 绘制节点连接
    const drawConnections = () => {
      const maxDistance = 200;

      nodesRef.current.forEach((node, i) => {
        node.connections = [];

        nodesRef.current.forEach((other, j) => {
          if (i >= j) return;

          const dx = other.x - node.x;
          const dy = other.y - node.y;
          const distance = Math.sqrt(dx * dx + dy * dy);

          if (distance < maxDistance) {
            node.connections.push(j);

            // 绘制连接线
            const opacity = (1 - distance / maxDistance) * 0.3;
            ctx.strokeStyle = `rgba(79, 195, 247, ${opacity})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(node.x, node.y);
            ctx.lineTo(other.x, other.y);
            ctx.stroke();

            // 随机生成数据包
            if (
              Math.random() > 0.998 &&
              packetsRef.current.length < 15
            ) {
              packetsRef.current.push({
                from: i,
                to: j,
                progress: 0,
                speed: 0.01 + Math.random() * 0.02,
              });
            }
          }
        });
      });
    };

    // 绘制数据包
    const drawDataPackets = () => {
      packetsRef.current = packetsRef.current.filter((packet) => {
        const fromNode = nodesRef.current[packet.from];
        const toNode = nodesRef.current[packet.to];

        if (!fromNode || !toNode) return false;

        packet.progress += packet.speed;

        if (packet.progress >= 1) {
          // 到达目标，创建脉冲效果
          toNode.pulsePhase = 0;
          return false;
        }

        // 插值计算当前位置
        const x = fromNode.x + (toNode.x - fromNode.x) * packet.progress;
        const y = fromNode.y + (toNode.y - fromNode.y) * packet.progress;

        // 绘制数据包光点
        const gradient = ctx.createRadialGradient(x, y, 0, x, y, 8);
        gradient.addColorStop(0, "rgba(79, 195, 247, 1)");
        gradient.addColorStop(0.5, "rgba(79, 195, 247, 0.5)");
        gradient.addColorStop(1, "rgba(79, 195, 247, 0)");

        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.arc(x, y, 8, 0, Math.PI * 2);
        ctx.fill();

        // 绘制拖尾效果
        ctx.strokeStyle = "rgba(79, 195, 247, 0.3)";
        ctx.lineWidth = 2;
        ctx.beginPath();
        const trailLength = 0.15;
        const trailProgress = Math.max(0, packet.progress - trailLength);
        const trailX =
          fromNode.x + (toNode.x - fromNode.x) * trailProgress;
        const trailY =
          fromNode.y + (toNode.y - fromNode.y) * trailProgress;
        ctx.moveTo(trailX, trailY);
        ctx.lineTo(x, y);
        ctx.stroke();

        return true;
      });
    };

    // 绘制节点
    const drawNodes = () => {
      nodesRef.current.forEach((node) => {
        const pulse = Math.sin(node.pulsePhase) * 0.5 + 0.5;
        const baseSize = node.isBlock ? 5 : 3;
        const size = baseSize + pulse * 2;

        if (node.isBlock) {
          // 区块节点 - 方形，带外发光
          const glowSize = size + 8;
          const gradient = ctx.createRadialGradient(
            node.x,
            node.y,
            0,
            node.x,
            node.y,
            glowSize
          );
          gradient.addColorStop(0, "rgba(255, 193, 7, 0.6)");
          gradient.addColorStop(0.5, "rgba(255, 193, 7, 0.2)");
          gradient.addColorStop(1, "rgba(255, 193, 7, 0)");

          ctx.fillStyle = gradient;
          ctx.beginPath();
          ctx.arc(node.x, node.y, glowSize, 0, Math.PI * 2);
          ctx.fill();

          // 方形核心
          ctx.fillStyle = `rgba(255, 193, 7, ${0.8 + pulse * 0.2})`;
          ctx.fillRect(
            node.x - size / 2,
            node.y - size / 2,
            size,
            size
          );

          // 边框
          ctx.strokeStyle = "rgba(255, 255, 255, 0.5)";
          ctx.lineWidth = 1;
          ctx.strokeRect(
            node.x - size / 2,
            node.y - size / 2,
            size,
            size
          );
        } else {
          // 普通节点 - 圆形
          const gradient = ctx.createRadialGradient(
            node.x,
            node.y,
            0,
            node.x,
            node.y,
            size + 4
          );
          gradient.addColorStop(0, "rgba(79, 195, 247, 1)");
          gradient.addColorStop(0.6, "rgba(79, 195, 247, 0.4)");
          gradient.addColorStop(1, "rgba(79, 195, 247, 0)");

          ctx.fillStyle = gradient;
          ctx.beginPath();
          ctx.arc(node.x, node.y, size + 4, 0, Math.PI * 2);
          ctx.fill();

          // 实心核心
          ctx.fillStyle = `rgba(79, 195, 247, ${0.9 + pulse * 0.1})`;
          ctx.beginPath();
          ctx.arc(node.x, node.y, size, 0, Math.PI * 2);
          ctx.fill();
        }
      });
    };

    // 动画循环
    const animate = () => {
      timeRef.current += 1;

      // 清空画布
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // 绘制顺序
      drawGrid();
      drawScanLine();
      updateNodes();
      drawConnections();
      drawDataPackets();
      drawNodes();

      animationRef.current = requestAnimationFrame(animate);
    };

    animate();

    // 清理
    return () => {
      window.removeEventListener("resize", resize);
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none z-0"
      style={{ opacity: 0.4 }}
    />
  );
}
