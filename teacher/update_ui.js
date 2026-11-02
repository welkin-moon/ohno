'use strict';
// Local teacher UI only. No third-party script, storage or credential logging.
const form = document.getElementById('update-approval');
if (form) {
  let pending = null;
  const button = form.querySelector('button[type="submit"]');
  const cancel = document.getElementById('cancel-update-upload');
  const status = document.getElementById('update-upload-status');
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (pending) return;
    const file = form.querySelector('input[type="file"]').files[0];
    if (!file || file.size < 1024 || file.size > 268435456) {
      status.textContent = '请选择 1 KiB–256 MiB 的 OHNO 更新包。'; return;
    }
    pending = new AbortController(); button.disabled = true; cancel.disabled = false;
    status.textContent = '正在验证并批准；未成功返回前，请勿认为已发布。';
    try {
      const response = await fetch('/updates/approve', { method: 'POST', redirect: 'error',
        headers: { 'Content-Type': 'application/octet-stream', 'X-Ohno-CSRF': form.elements.csrf.value },
        body: file, signal: pending.signal });
      if (!response.ok) throw new Error('server rejected');
      location.reload();
    } catch (error) {
      // Cancellation can race the durable server decision. Never claim that a
      // timed-out/disconnected request proves approval did not occur.
      status.textContent = '请求未确认，请刷新查看当前批准状态，再决定重试或暂停。';
    } finally {
      pending = null; button.disabled = false; cancel.disabled = true;
    }
  });
  cancel.addEventListener('click', () => { if (pending) pending.abort(); });
  window.addEventListener('pagehide', () => { if (pending) pending.abort(); });
}
