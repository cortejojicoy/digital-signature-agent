import { createRoot } from 'react-dom/client';

import { App } from './App';
import './styles.css';

const root = document.getElementById('root')!;
createRoot(root).render(<App />);

// The window is as tall as what's in it: report the content height whenever
// it changes, and the main process resizes the window (within the screen).
// Open dialogs ([data-fit-overlay]) are position: fixed, so they don't add to
// the page's height; count their full height too. A timer, not
// requestAnimationFrame: the window is still hidden for the first fit.
function fitWindowToContent(): void {
  let last = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const measure = () => {
    timer = undefined;
    let height = root.scrollHeight;
    for (const overlay of document.querySelectorAll<HTMLElement>('[data-fit-overlay]')) {
      // scrollHeight leaves out borders; the backdrop pads 16px above and below.
      height = Math.max(height, overlay.scrollHeight + (overlay.offsetHeight - overlay.clientHeight) + 32);
    }
    height = Math.ceil(height);
    if (height !== last) {
      last = height;
      void window.agent.fitContent(height);
    }
  };
  const schedule = () => {
    timer ??= setTimeout(measure, 16);
  };

  const resize = new ResizeObserver(schedule);
  resize.observe(root);
  new MutationObserver(() => {
    for (const overlay of document.querySelectorAll('[data-fit-overlay]')) resize.observe(overlay);
    schedule();
  }).observe(document.body, { childList: true, subtree: true });
  schedule();
}

fitWindowToContent();
