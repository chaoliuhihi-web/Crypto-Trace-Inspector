export function TechCorners() {
  return (
    <>
      {/* 左上角装饰 */}
      <div className="fixed top-0 left-0 w-32 h-32 pointer-events-none z-[5]">
        <svg className="w-full h-full" viewBox="0 0 100 100">
          {/* 外框 */}
          <path
            d="M 0 20 L 0 0 L 20 0"
            stroke="rgba(79, 195, 247, 0.4)"
            strokeWidth="1"
            fill="none"
          />
          {/* 内框 */}
          <path
            d="M 5 15 L 5 5 L 15 5"
            stroke="rgba(79, 195, 247, 0.6)"
            strokeWidth="1.5"
            fill="none"
          />
          {/* 装饰线 */}
          <line
            x1="0"
            y1="25"
            x2="8"
            y2="25"
            stroke="rgba(79, 195, 247, 0.3)"
            strokeWidth="1"
          />
          <line
            x1="25"
            y1="0"
            x2="25"
            y2="8"
            stroke="rgba(79, 195, 247, 0.3)"
            strokeWidth="1"
          />
          {/* 角点 */}
          <circle
            cx="0"
            cy="0"
            r="2"
            fill="rgba(79, 195, 247, 0.8)"
          />
        </svg>
      </div>

      {/* 右上角装饰 */}
      <div className="fixed top-0 right-0 w-32 h-32 pointer-events-none z-[5]">
        <svg className="w-full h-full" viewBox="0 0 100 100">
          <path
            d="M 80 0 L 100 0 L 100 20"
            stroke="rgba(79, 195, 247, 0.4)"
            strokeWidth="1"
            fill="none"
          />
          <path
            d="M 85 5 L 95 5 L 95 15"
            stroke="rgba(79, 195, 247, 0.6)"
            strokeWidth="1.5"
            fill="none"
          />
          <line
            x1="92"
            y1="25"
            x2="100"
            y2="25"
            stroke="rgba(79, 195, 247, 0.3)"
            strokeWidth="1"
          />
          <line
            x1="75"
            y1="0"
            x2="75"
            y2="8"
            stroke="rgba(79, 195, 247, 0.3)"
            strokeWidth="1"
          />
          <circle
            cx="100"
            cy="0"
            r="2"
            fill="rgba(79, 195, 247, 0.8)"
          />
        </svg>
      </div>

      {/* 左下角装饰 */}
      <div className="fixed bottom-0 left-0 w-32 h-32 pointer-events-none z-[5]">
        <svg className="w-full h-full" viewBox="0 0 100 100">
          <path
            d="M 0 80 L 0 100 L 20 100"
            stroke="rgba(79, 195, 247, 0.4)"
            strokeWidth="1"
            fill="none"
          />
          <path
            d="M 5 85 L 5 95 L 15 95"
            stroke="rgba(79, 195, 247, 0.6)"
            strokeWidth="1.5"
            fill="none"
          />
          <line
            x1="0"
            y1="75"
            x2="8"
            y2="75"
            stroke="rgba(79, 195, 247, 0.3)"
            strokeWidth="1"
          />
          <line
            x1="25"
            y1="92"
            x2="25"
            y2="100"
            stroke="rgba(79, 195, 247, 0.3)"
            strokeWidth="1"
          />
          <circle
            cx="0"
            cy="100"
            r="2"
            fill="rgba(79, 195, 247, 0.8)"
          />
        </svg>
      </div>

      {/* 右下角装饰 */}
      <div className="fixed bottom-0 right-0 w-32 h-32 pointer-events-none z-[5]">
        <svg className="w-full h-full" viewBox="0 0 100 100">
          <path
            d="M 80 100 L 100 100 L 100 80"
            stroke="rgba(79, 195, 247, 0.4)"
            strokeWidth="1"
            fill="none"
          />
          <path
            d="M 85 95 L 95 95 L 95 85"
            stroke="rgba(79, 195, 247, 0.6)"
            strokeWidth="1.5"
            fill="none"
          />
          <line
            x1="92"
            y1="75"
            x2="100"
            y2="75"
            stroke="rgba(79, 195, 247, 0.3)"
            strokeWidth="1"
          />
          <line
            x1="75"
            y1="92"
            x2="75"
            y2="100"
            stroke="rgba(79, 195, 247, 0.3)"
            strokeWidth="1"
          />
          <circle
            cx="100"
            cy="100"
            r="2"
            fill="rgba(79, 195, 247, 0.8)"
          />
        </svg>
      </div>

      {/* 顶部中央装饰条 */}
      <div className="fixed top-0 left-1/2 -translate-x-1/2 w-64 h-1 pointer-events-none z-[5]">
        <div className="w-full h-full bg-gradient-to-r from-transparent via-[rgba(79,195,247,0.4)] to-transparent" />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-16 h-[2px] bg-gradient-to-r from-transparent via-[rgba(79,195,247,0.8)] to-transparent" />
      </div>
    </>
  );
}
